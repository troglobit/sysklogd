/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (C) 2026  Joachim Wiberg <troglobit@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * RFC 5848 - Signed Syslog Messages
 *
 * This implementation provides:
 * - Signature Blocks (SD-ID: ssign) containing message hashes + signature
 * - Certificate Blocks (SD-ID: ssign-cert) for key distribution
 * - Four signature group modes (SG=0,1,2,3)
 * - SHA-256 hashing (SHA-1 deprecated per RFC 5848 Section 4.2.1)
 * - DSA or RSA signatures using OpenSSL EVP interface
 *
 * References:
 * - RFC 5848: Signed Syslog Messages
 * - RFC 5424: The Syslog Protocol (structured data format)
 * - NetBSD syslogd (reference implementation)
 */

#include "config.h"

#ifdef HAVE_OPENSSL

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include "queue.h"
#include "sign.h"
#include "syslogd.h"
#include "timer.h"

/* Version "0121" = SHA-256, DSA-PGP (RFC 5848 Section 4.2.1) */
#define SIGN_VERSION "0121"

/* Maximum length of structured data for signature/certificate blocks */
#define SIGN_MAX_SD_LENGTH 4096

/* Maximum base64-encoded hash length (SHA-256 = 32 bytes -> 44 chars) */
#define SIGN_MAX_HASH_B64 48

/* Maximum base64-encoded signature length */
#define SIGN_MAX_SIG_B64 1024

/* Maximum payload bytes per certificate fragment (RFC 5848 Section 5.3.2.4) */
#define SIGN_CERT_FRAG_MAX 1024

/* Signature group structure - tracks hashes for a group of messages */
struct sign_group {
	LIST_ENTRY(sign_group) sg_link;
	int			sg_id;		/* Signature group ID */
	int			sg_spri;	/* Signature priority */
	uint64_t		sg_gbc;		/* Global block counter */
	uint64_t		sg_fmn;		/* First message number */
	uint64_t		sg_cnt;		/* Message count in block */
	char			sg_hashes[SIGN_MAX_HASHES][SIGN_MAX_HASH_B64];
	size_t			sg_hash_count;
	struct filed		*sg_filed;	/* For SG=3, destination filed */
};

LIST_HEAD(sign_groups, sign_group);
static struct sign_groups sign_group_list = LIST_HEAD_INITIALIZER(sign_group_list);

/* Signing configuration and state */
static EVP_PKEY *sign_privkey;		/* Private key for signing */
static X509     *sign_cert;		/* Certificate (optional) */
static char     *sign_pubkey_b64;	/* Base64-encoded public key */
static size_t    sign_pubkey_len;	/* Length of pubkey_b64 */
static uint64_t  sign_rsid;		/* Reboot Session ID (48 bits) */
static int       sign_sg_mode;		/* Signature group mode */
static int       sign_initialized;	/* Flag: signing is ready */
static uint64_t  sign_msgnum;		/* Global message number counter */
static int       sign_delim[8];		/* Priority delimiters for SG=2 */
static int       sign_delim_count;	/* Number of delimiters */
static int       sign_pending;		/* A group filled, flush after msg */

/* Configuration strings (set by cfparse) */
static char *cfg_keyfile;
static char *cfg_certfile;


/*
 * Base64 encode using OpenSSL
 */
static char *base64_encode(const unsigned char *data, size_t len, size_t *outlen)
{
	size_t b64len;
	char *b64;

	b64len = ((len + 2) / 3) * 4 + 1;
	b64 = malloc(b64len);
	if (!b64)
		return NULL;

	*outlen = EVP_EncodeBlock((unsigned char *)b64, data, len);
	b64[*outlen] = '\0';

	return b64;
}

/*
 * Load private key from PEM file
 */
static int sign_load_privkey(const char *keyfile)
{
	FILE *fp;

	fp = fopen(keyfile, "r");
	if (!fp) {
		ERR("sign: cannot open key file %s", keyfile);
		return -1;
	}

	sign_privkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);

	if (!sign_privkey) {
		ERRX("sign: failed to read private key from %s", keyfile);
		return -1;
	}

	return 0;
}

/*
 * Load certificate from PEM file (optional)
 */
static int sign_load_cert(const char *certfile)
{
	FILE *fp;
	BIO *bio = NULL;
	unsigned char *pubkey_der = NULL;
	int pubkey_len;

	fp = fopen(certfile, "r");
	if (!fp) {
		ERR("sign: cannot open certificate file %s", certfile);
		return -1;
	}

	sign_cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	if (!sign_cert) {
		ERRX("sign: failed to read certificate from %s", certfile);
		return -1;
	}

	/* Extract public key and encode to base64 for certificate blocks */
	bio = BIO_new(BIO_s_mem());
	if (!bio)
		goto err;

	if (!i2d_X509_PUBKEY_bio(bio, X509_get_X509_PUBKEY(sign_cert)))
		goto err;

	pubkey_len = BIO_get_mem_data(bio, &pubkey_der);
	if (pubkey_len <= 0)
		goto err;

	sign_pubkey_b64 = base64_encode(pubkey_der, pubkey_len, &sign_pubkey_len);
	BIO_free(bio);

	if (!sign_pubkey_b64) {
		ERRX("sign: failed to encode public key");
		return -1;
	}

	return 0;

err:
	if (bio)
		BIO_free(bio);
	ERRX("sign: failed to extract public key from certificate");
	return -1;
}

/*
 * Generate Reboot Session ID (RSID)
 * RFC 5848 Section 4.2.3: 48-bit random value
 */
static void sign_generate_rsid(void)
{
	unsigned char buf[6];

	if (RAND_bytes(buf, sizeof(buf)) != 1) {
		/* Fallback to time-based if RAND fails */
		uint64_t t = (uint64_t)time(NULL);
		sign_rsid = t & 0xFFFFFFFFFFFFULL;
	} else {
		sign_rsid = ((uint64_t)buf[0] << 40) |
			    ((uint64_t)buf[1] << 32) |
			    ((uint64_t)buf[2] << 24) |
			    ((uint64_t)buf[3] << 16) |
			    ((uint64_t)buf[4] << 8)  |
			    ((uint64_t)buf[5]);
	}
}

/*
 * Create a new signature group
 */
static struct sign_group *sign_group_create(int id, int spri, struct filed *f)
{
	struct sign_group *sg;

	sg = calloc(1, sizeof(*sg));
	if (!sg)
		return NULL;

	sg->sg_id = id;
	sg->sg_spri = spri;
	sg->sg_gbc = 1;
	sg->sg_fmn = sign_msgnum + 1;
	sg->sg_filed = f;

	LIST_INSERT_HEAD(&sign_group_list, sg, sg_link);

	return sg;
}

/*
 * Find or create signature group for a message
 */
static struct sign_group *sign_get_group(struct filed *f, int pri)
{
	struct sign_group *sg;
	int id = 0;
	int spri = 0;

	switch (sign_sg_mode) {
	case SIGN_SG_GLOBAL:
		/* SG=0: Single group for all messages */
		id = 0;
		spri = 0;
		break;

	case SIGN_SG_PRIORITY:
		/* SG=1: One group per priority (facility*8 + severity) */
		id = LOG_FAC(pri) * 8 + LOG_PRI(pri);
		spri = pri;
		break;

	case SIGN_SG_RANGE:
		/* SG=2: Priority ranges using delimiters */
		id = 0;
		for (int i = 0; i < sign_delim_count; i++) {
			if (pri <= sign_delim[i])
				break;
			id++;
		}
		spri = id < sign_delim_count ? sign_delim[id] : 191;
		break;

	case SIGN_SG_DEST:
		/* SG=3: One group per destination (NetBSD extension) */
		LIST_FOREACH(sg, &sign_group_list, sg_link) {
			if (sg->sg_filed == f)
				return sg;
		}
		/* Create new group for this destination */
		return sign_group_create(0, 0, f);

	default:
		return NULL;
	}

	/* For SG=0,1,2: Find existing group or create new */
	LIST_FOREACH(sg, &sign_group_list, sg_link) {
		if (sg->sg_id == id && sg->sg_spri == spri &&
		    sign_sg_mode != SIGN_SG_DEST)
			return sg;
	}

	return sign_group_create(id, spri, NULL);
}

/*
 * Compute SHA-256 hash of message per RFC 5848 Section 4.2.8
 *
 * Hash input is: PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP
 *                PROCID SP MSGID SP STRUCTURED-DATA SP MSG
 */
static int sign_compute_hash(struct buf_msg *msg, char *hash_b64, size_t hash_b64_sz)
{
	EVP_MD_CTX *ctx;
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hash_len;
	const char *sp = " ";
	const char *nil = "-";
	size_t b64len;
	char *b64;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return -1;

	if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	/* Hash message components per RFC 5848 Section 4.2.8 */
	EVP_DigestUpdate(ctx, msg->pribuf, strlen(msg->pribuf));
	EVP_DigestUpdate(ctx, "1", 1);	/* VERSION */
	EVP_DigestUpdate(ctx, sp, 1);
	EVP_DigestUpdate(ctx, msg->timebuf, strlen(msg->timebuf));
	EVP_DigestUpdate(ctx, sp, 1);
	EVP_DigestUpdate(ctx, msg->hostname ? msg->hostname : nil,
			 msg->hostname ? strlen(msg->hostname) : 1);
	EVP_DigestUpdate(ctx, sp, 1);
	EVP_DigestUpdate(ctx, msg->app_name ? msg->app_name : nil,
			 msg->app_name ? strlen(msg->app_name) : 1);
	EVP_DigestUpdate(ctx, sp, 1);
	EVP_DigestUpdate(ctx, msg->proc_id ? msg->proc_id : nil,
			 msg->proc_id ? strlen(msg->proc_id) : 1);
	EVP_DigestUpdate(ctx, sp, 1);
	EVP_DigestUpdate(ctx, msg->msgid ? msg->msgid : nil,
			 msg->msgid ? strlen(msg->msgid) : 1);
	EVP_DigestUpdate(ctx, sp, 1);
	EVP_DigestUpdate(ctx, msg->sd ? msg->sd : nil,
			 msg->sd ? strlen(msg->sd) : 1);
	EVP_DigestUpdate(ctx, sp, 1);
	EVP_DigestUpdate(ctx, msg->msg ? msg->msg : "",
			 msg->msg ? strlen(msg->msg) : 0);

	if (!EVP_DigestFinal_ex(ctx, hash, &hash_len)) {
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	EVP_MD_CTX_free(ctx);

	/* Base64 encode the hash */
	b64 = base64_encode(hash, hash_len, &b64len);
	if (!b64)
		return -1;

	if (b64len >= hash_b64_sz) {
		free(b64);
		return -1;
	}

	strlcpy(hash_b64, b64, hash_b64_sz);
	free(b64);

	return 0;
}

/*
 * Sign data using private key
 */
static char *sign_data(const unsigned char *data, size_t data_len)
{
	EVP_MD_CTX *ctx;
	unsigned char *sig = NULL;
	size_t sig_len;
	char *sig_b64 = NULL;
	size_t b64len;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return NULL;

	if (!EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, sign_privkey))
		goto err;

	if (!EVP_DigestSignUpdate(ctx, data, data_len))
		goto err;

	/* Get signature length */
	if (!EVP_DigestSignFinal(ctx, NULL, &sig_len))
		goto err;

	sig = malloc(sig_len);
	if (!sig)
		goto err;

	if (!EVP_DigestSignFinal(ctx, sig, &sig_len))
		goto err;

	/* Base64 encode signature */
	sig_b64 = base64_encode(sig, sig_len, &b64len);

err:
	EVP_MD_CTX_free(ctx);
	free(sig);

	return sig_b64;
}

/*
 * Format and send a signature block
 * RFC 5848 Section 4.2: [ssign VER RSID SG SPRI GBC FMN CNT HB SIGN]
 */
static void sign_send_sig_block(struct sign_group *sg)
{
	char sd[SIGN_MAX_SD_LENGTH];
	char hb[SIGN_MAX_SD_LENGTH];
	char *sig_b64;
	size_t hb_len = 0;

	if (sg->sg_hash_count == 0)
		return;

	/* Build hash block (space-separated base64 hashes) */
	hb[0] = '\0';
	for (size_t i = 0; i < sg->sg_hash_count; i++) {
		if (i > 0)
			hb_len += snprintf(hb + hb_len, sizeof(hb) - hb_len, " ");
		hb_len += snprintf(hb + hb_len, sizeof(hb) - hb_len, "%s",
				   sg->sg_hashes[i]);
	}

	/* Build data to sign: VER RSID SG SPRI GBC FMN CNT HB */
	char signdata[SIGN_MAX_SD_LENGTH];
	snprintf(signdata, sizeof(signdata),
		 "%s %lu %d %d %lu %lu %zu %s",
		 SIGN_VERSION, (unsigned long)sign_rsid, sg->sg_id,
		 sg->sg_spri, (unsigned long)sg->sg_gbc,
		 (unsigned long)sg->sg_fmn, sg->sg_hash_count, hb);

	sig_b64 = sign_data((unsigned char *)signdata, strlen(signdata));
	if (!sig_b64) {
		ERRX("sign: failed to create signature");
		return;
	}

	/* Format signature block structured data */
	snprintf(sd, sizeof(sd),
		 "[ssign VER=\"%s\" RSID=\"%lu\" SG=\"%d\" SPRI=\"%d\" "
		 "GBC=\"%lu\" FMN=\"%lu\" CNT=\"%zu\" HB=\"%s\" SIGN=\"%s\"]",
		 SIGN_VERSION, (unsigned long)sign_rsid, sg->sg_id,
		 sg->sg_spri, (unsigned long)sg->sg_gbc,
		 (unsigned long)sg->sg_fmn, sg->sg_hash_count,
		 hb, sig_b64);

	free(sig_b64);

	/* Update group state for next block */
	sg->sg_gbc++;
	sg->sg_fmn = sign_msgnum + 1;
	sg->sg_hash_count = 0;
	sg->sg_cnt = 0;

	/* Emit the [ssign] block as an RFC5424 message to all destinations */
	sign_emit_block("SIGN", sd);
}

/*
 * Parse sign_delim_sg2 configuration (space-separated priority values)
 */
static int sign_parse_delim(const char *delim_str)
{
	char *str, *p, *saveptr;

	if (!delim_str || !*delim_str)
		return 0;

	str = strdup(delim_str);
	if (!str)
		return -1;

	sign_delim_count = 0;
	p = strtok_r(str, " \t", &saveptr);
	while (p && sign_delim_count < 8) {
		sign_delim[sign_delim_count++] = atoi(p);
		p = strtok_r(NULL, " \t", &saveptr);
	}

	free(str);
	return 0;
}


/*
 * Public API: Configure signing from parsed config values
 */
int sign_config(const char *sg_str, const char *delim_str,
		const char *keyfile, const char *certfile)
{
	/* sg_str is required to enable signing */
	if (!sg_str || !*sg_str)
		return 0;  /* Signing not enabled */

	sign_sg_mode = atoi(sg_str);
	if (sign_sg_mode < 0 || sign_sg_mode > 3) {
		ERRX("sign: invalid sign_sg value %d (must be 0-3)", sign_sg_mode);
		return -1;
	}

	/* Parse SG=2 delimiters if provided */
	if (sign_sg_mode == SIGN_SG_RANGE && delim_str)
		sign_parse_delim(delim_str);

	/* Store key/cert paths for sign_init */
	free(cfg_keyfile);
	free(cfg_certfile);
	cfg_keyfile = keyfile ? strdup(keyfile) : NULL;
	cfg_certfile = certfile ? strdup(certfile) : NULL;

	return 0;
}

/*
 * Public API: Initialize signing subsystem
 */
int sign_init(void)
{
	/* Apply once, like tls_init(): a SIGHUP must not re-add the timer
	 * or reset the RSID and message counter mid-session. */
	if (sign_initialized)
		return 0;

	/* If no keyfile configured, signing is disabled */
	if (!cfg_keyfile) {
		sign_initialized = 0;
		return 0;
	}

	/* Load private key */
	if (sign_load_privkey(cfg_keyfile) < 0)
		return -1;

	/* Load certificate if provided */
	if (cfg_certfile && sign_load_cert(cfg_certfile) < 0) {
		EVP_PKEY_free(sign_privkey);
		sign_privkey = NULL;
		return -1;
	}

	/* Generate RSID for this session */
	sign_generate_rsid();

	/* Register timer for periodic signature blocks */
	timer_add(SIGN_BLOCK_INTERVAL, sign_send_blocks, NULL);

	sign_initialized = 1;
	sign_msgnum = 0;

	NOTE("RFC5848 signing enabled, SG=%d RSID=%lu",
	     sign_sg_mode, (unsigned long)sign_rsid);

	/* Send initial certificate block if we have a certificate */
	if (sign_cert)
		sign_send_cert_block();

	return 0;
}

/*
 * Public API: Shutdown signing subsystem
 */
void sign_exit(void)
{
	struct sign_group *sg, *tmp;

	if (!sign_initialized)
		return;

	/* Send final signature blocks for all groups */
	LIST_FOREACH(sg, &sign_group_list, sg_link) {
		if (sg->sg_hash_count > 0)
			sign_send_sig_block(sg);
	}

	/* Free signature groups */
	LIST_FOREACH_SAFE(sg, &sign_group_list, sg_link, tmp) {
		LIST_REMOVE(sg, sg_link);
		free(sg);
	}

	/* Free OpenSSL resources */
	if (sign_privkey) {
		EVP_PKEY_free(sign_privkey);
		sign_privkey = NULL;
	}
	if (sign_cert) {
		X509_free(sign_cert);
		sign_cert = NULL;
	}
	free(sign_pubkey_b64);
	sign_pubkey_b64 = NULL;

	free(cfg_keyfile);
	free(cfg_certfile);
	cfg_keyfile = NULL;
	cfg_certfile = NULL;

	sign_initialized = 0;
}

/*
 * Public API: Check if signing is enabled
 */
int sign_enabled(void)
{
	return sign_initialized;
}

/*
 * Public API: Advance the message counter, once per message
 */
void sign_msg_begin(void)
{
	if (sign_initialized)
		sign_msgnum++;
}

/*
 * Public API: Compute and store hash for a message
 */
void sign_msg_hash(struct buf_msg *msg, struct filed *f)
{
	struct sign_group *sg;

	if (!sign_initialized)
		return;

	/* Get signature group for this message */
	sg = sign_get_group(f, msg->pri);
	if (!sg)
		return;

	/*
	 * If the group is full, defer the block emission to after the
	 * message has been distributed (see sign_flush_blocks); emitting
	 * here would re-enter the logmsg() destination loop.
	 */
	if (sg->sg_hash_count >= SIGN_MAX_HASHES) {
		sign_pending = 1;
		return;
	}

	/* Compute and store hash */
	if (sign_compute_hash(msg, sg->sg_hashes[sg->sg_hash_count],
			      sizeof(sg->sg_hashes[0])) == 0) {
		sg->sg_hash_count++;
		sg->sg_cnt++;
		if (sg->sg_hash_count >= SIGN_MAX_HASHES)
			sign_pending = 1;
	}
}

/*
 * Public API: Emit signature blocks for groups that filled while hashing
 * the current message.  Called after the logmsg() destination loop.
 */
void sign_flush_blocks(void)
{
	struct sign_group *sg;

	if (!sign_initialized || !sign_pending)
		return;

	sign_pending = 0;
	LIST_FOREACH(sg, &sign_group_list, sg_link) {
		if (sg->sg_hash_count >= SIGN_MAX_HASHES)
			sign_send_sig_block(sg);
	}
}

/*
 * Public API: Timer callback to send signature blocks
 */
void sign_send_blocks(void *arg)
{
	struct sign_group *sg;

	(void)arg;

	if (!sign_initialized)
		return;

	LIST_FOREACH(sg, &sign_group_list, sg_link) {
		if (sg->sg_hash_count > 0)
			sign_send_sig_block(sg);
	}
}

/*
 * Public API: Send certificate block
 * RFC 5848 Section 4.3 - Certificate Block format
 */
void sign_send_cert_block(void)
{
	char sd[SIGN_MAX_SD_LENGTH];
	char *sig_b64;
	size_t total_len;
	size_t frag_offset = 0;
	int index = 1;

	if (!sign_initialized || !sign_cert || !sign_pubkey_b64)
		return;

	total_len = sign_pubkey_len;

	/* Fragment large certificates per RFC 5848 Section 5.3.2.4 */
	while (frag_offset < total_len) {
		size_t frag_len = total_len - frag_offset;
		if (frag_len > SIGN_CERT_FRAG_MAX)
			frag_len = SIGN_CERT_FRAG_MAX;

		/* Build data to sign for this fragment */
		char signdata[SIGN_MAX_SD_LENGTH];
		snprintf(signdata, sizeof(signdata),
			 "%s %lu %d 0 %zu %d %zu %.*s",
			 SIGN_VERSION, (unsigned long)sign_rsid, sign_sg_mode,
			 total_len, index, frag_len,
			 (int)frag_len, sign_pubkey_b64 + frag_offset);

		sig_b64 = sign_data((unsigned char *)signdata, strlen(signdata));
		if (!sig_b64) {
			ERRX("sign: failed to sign certificate block");
			return;
		}

		/* Format certificate block structured data */
		snprintf(sd, sizeof(sd),
			 "[ssign-cert VER=\"%s\" RSID=\"%lu\" SG=\"%d\" SPRI=\"0\" "
			 "TBPL=\"%zu\" INDEX=\"%d\" FLEN=\"%zu\" FRAG=\"%.*s\" "
			 "SIGN=\"%s\"]",
			 SIGN_VERSION, (unsigned long)sign_rsid, sign_sg_mode,
			 total_len, index, frag_len,
			 (int)frag_len, sign_pubkey_b64 + frag_offset,
			 sig_b64);

		free(sig_b64);

		/* Emit the [ssign-cert] block as an RFC5424 message */
		sign_emit_block("CERT", sd);

		frag_offset += frag_len;
		index++;
	}
}

#endif /* HAVE_OPENSSL */
