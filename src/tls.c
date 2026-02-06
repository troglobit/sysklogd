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
 * RFC 5425 - Transport Layer Security (TLS) Transport Mapping for Syslog
 *
 * This implementation provides:
 * - TLS 1.2+ encrypted syslog transport (RFC 5425)
 * - Server-side TLS for receiving syslog messages
 * - Client-side TLS for forwarding syslog messages
 * - Certificate verification: chain, fingerprint, hostname
 * - Optional mutual TLS authentication
 *
 * References:
 * - RFC 5425: Transport Layer Security (TLS) Transport Mapping for Syslog
 * - RFC 6587: Transmission of Syslog Messages over TCP
 * - OpenBSD syslogd (URL syntax inspiration)
 * - NetBSD syslogd (fingerprint verification reference)
 */

#include "config.h"

#ifdef HAVE_OPENSSL

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "syslogd.h"
#include "tls.h"

/* TLS configuration */
static char *tls_keyfile;
static char *tls_certfile;
static char *tls_cafile;
static char *tls_capath;
static int   tls_verify_mode = TLS_VERIFY_OFF;

/* SSL contexts */
static SSL_CTX *tls_server_ctx;
static SSL_CTX *tls_client_ctx;

/* Flag indicating TLS is configured and ready */
static int tls_ready;

/* Helper to log OpenSSL errors */
static void tls_log_errors(const char *context)
{
	unsigned long err;
	char buf[256];

	while ((err = ERR_get_error()) != 0) {
		ERR_error_string_n(err, buf, sizeof(buf));
		ERRX("TLS %s: %s", context, buf);
	}
}

/* Convert string to verification mode */
static int tls_parse_verify(const char *str)
{
	if (!str || !*str || !strcasecmp(str, "off") || !strcasecmp(str, "no"))
		return TLS_VERIFY_OFF;
	if (!strcasecmp(str, "optional"))
		return TLS_VERIFY_OPTIONAL;
	if (!strcasecmp(str, "required") || !strcasecmp(str, "on") || !strcasecmp(str, "yes"))
		return TLS_VERIFY_REQUIRED;
	if (!strcasecmp(str, "hostname"))
		return TLS_VERIFY_HOSTNAME;
	/* Fingerprint is set via per-action option, not global */
	return TLS_VERIFY_OFF;
}

int tls_config(const char *keyfile, const char *certfile,
               const char *cafile, const char *capath, const char *verify)
{
	/* Free any previous configuration */
	free(tls_keyfile);
	free(tls_certfile);
	free(tls_cafile);
	free(tls_capath);

	tls_keyfile = keyfile ? strdup(keyfile) : NULL;
	tls_certfile = certfile ? strdup(certfile) : NULL;
	tls_cafile = cafile ? strdup(cafile) : NULL;
	tls_capath = capath ? strdup(capath) : NULL;
	tls_verify_mode = tls_parse_verify(verify);

	return 0;
}

int tls_init(void)
{
	const SSL_METHOD *method;

	/* Already initialized? */
	if (tls_ready)
		return 0;

	/* Initialize OpenSSL (may already be done by sign.c) */
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	/* Create server context if we have server credentials */
	if (tls_keyfile && tls_certfile) {
		method = TLS_server_method();
		tls_server_ctx = SSL_CTX_new(method);
		if (!tls_server_ctx) {
			tls_log_errors("server context creation");
			return -1;
		}

		/* Set minimum TLS version to 1.2 per RFC 5425 */
		SSL_CTX_set_min_proto_version(tls_server_ctx, TLS1_2_VERSION);

		/* Load server certificate */
		if (SSL_CTX_use_certificate_file(tls_server_ctx, tls_certfile,
						 SSL_FILETYPE_PEM) != 1) {
			tls_log_errors("loading server certificate");
			SSL_CTX_free(tls_server_ctx);
			tls_server_ctx = NULL;
			return -1;
		}

		/* Load server private key */
		if (SSL_CTX_use_PrivateKey_file(tls_server_ctx, tls_keyfile,
						SSL_FILETYPE_PEM) != 1) {
			tls_log_errors("loading server private key");
			SSL_CTX_free(tls_server_ctx);
			tls_server_ctx = NULL;
			return -1;
		}

		/* Verify private key matches certificate */
		if (SSL_CTX_check_private_key(tls_server_ctx) != 1) {
			tls_log_errors("private key verification");
			SSL_CTX_free(tls_server_ctx);
			tls_server_ctx = NULL;
			return -1;
		}

		/* Configure client certificate verification */
		if (tls_verify_mode >= TLS_VERIFY_REQUIRED) {
			SSL_CTX_set_verify(tls_server_ctx,
					   SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
					   NULL);
		} else if (tls_verify_mode == TLS_VERIFY_OPTIONAL) {
			SSL_CTX_set_verify(tls_server_ctx, SSL_VERIFY_PEER, NULL);
		} else {
			SSL_CTX_set_verify(tls_server_ctx, SSL_VERIFY_NONE, NULL);
		}

		/* Load CA certificates for client verification */
		if (tls_cafile || tls_capath) {
			if (SSL_CTX_load_verify_locations(tls_server_ctx,
							  tls_cafile, tls_capath) != 1) {
				tls_log_errors("loading CA certificates");
			}
		}

		NOTE("TLS server context initialized");
	}

	/* Create client context for forwarding */
	method = TLS_client_method();
	tls_client_ctx = SSL_CTX_new(method);
	if (!tls_client_ctx) {
		tls_log_errors("client context creation");
		if (tls_server_ctx) {
			SSL_CTX_free(tls_server_ctx);
			tls_server_ctx = NULL;
		}
		return -1;
	}

	/* Set minimum TLS version to 1.2 per RFC 5425 */
	SSL_CTX_set_min_proto_version(tls_client_ctx, TLS1_2_VERSION);

	/* Load CA certificates for server verification */
	if (tls_cafile || tls_capath) {
		if (SSL_CTX_load_verify_locations(tls_client_ctx,
						  tls_cafile, tls_capath) != 1) {
			tls_log_errors("loading CA certificates for client");
		}
	} else {
		/* Use default CA paths */
		SSL_CTX_set_default_verify_paths(tls_client_ctx);
	}

	NOTE("TLS client context initialized");
	tls_ready = 1;

	return 0;
}

void tls_exit(void)
{
	if (tls_server_ctx) {
		SSL_CTX_free(tls_server_ctx);
		tls_server_ctx = NULL;
	}
	if (tls_client_ctx) {
		SSL_CTX_free(tls_client_ctx);
		tls_client_ctx = NULL;
	}

	free(tls_keyfile);
	free(tls_certfile);
	free(tls_cafile);
	free(tls_capath);
	tls_keyfile = NULL;
	tls_certfile = NULL;
	tls_cafile = NULL;
	tls_capath = NULL;

	tls_ready = 0;
}

int tls_enabled(void)
{
	return tls_ready;
}

int tls_accept(struct tcp_conn *tc)
{
	SSL *ssl;
	int rc, err;

	if (!tls_server_ctx) {
		ERRX("TLS accept: server context not initialized");
		return -1;
	}

	ssl = SSL_new(tls_server_ctx);
	if (!ssl) {
		tls_log_errors("SSL_new");
		return -1;
	}

	if (SSL_set_fd(ssl, tc->tc_sd) != 1) {
		tls_log_errors("SSL_set_fd");
		SSL_free(ssl);
		return -1;
	}

	tc->tc_ssl = ssl;
	tc->tc_tls_handshake = 1;

	rc = SSL_accept(ssl);
	if (rc == 1) {
		tc->tc_tls_handshake = 0;
		return 0;
	}

	err = SSL_get_error(ssl, rc);
	if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
		return 1; /* Handshake in progress */
	}

	tls_log_errors("SSL_accept");
	SSL_free(ssl);
	tc->tc_ssl = NULL;
	tc->tc_tls_handshake = 0;
	return -1;
}

int tls_accept_continue(struct tcp_conn *tc)
{
	int rc, err;

	if (!tc->tc_ssl || !tc->tc_tls_handshake)
		return -1;

	rc = SSL_accept(tc->tc_ssl);
	if (rc == 1) {
		tc->tc_tls_handshake = 0;
		return 0;
	}

	err = SSL_get_error(tc->tc_ssl, rc);
	if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
		return 1; /* Still in progress */
	}

	tls_log_errors("SSL_accept continue");
	SSL_free(tc->tc_ssl);
	tc->tc_ssl = NULL;
	tc->tc_tls_handshake = 0;
	return -1;
}

int tls_connect(struct filed *f)
{
	SSL *ssl;
	int rc, err;

	if (!tls_client_ctx) {
		ERRX("TLS connect: client context not initialized");
		return -1;
	}

	if (f->f_un.f_forw.f_tcp_sd < 0) {
		ERRX("TLS connect: no TCP connection");
		return -1;
	}

	ssl = SSL_new(tls_client_ctx);
	if (!ssl) {
		tls_log_errors("SSL_new for connect");
		return -1;
	}

	if (SSL_set_fd(ssl, f->f_un.f_forw.f_tcp_sd) != 1) {
		tls_log_errors("SSL_set_fd for connect");
		SSL_free(ssl);
		return -1;
	}

	/* Set SNI hostname */
	SSL_set_tlsext_host_name(ssl, f->f_un.f_forw.f_hname);

	/* Configure verification based on per-action settings */
	if (f->f_un.f_forw.f_tls_verify == TLS_VERIFY_OFF) {
		SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
	} else {
		SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
	}

	f->f_un.f_forw.f_ssl = ssl;
	f->f_un.f_forw.f_tls_handshake = 1;

	rc = SSL_connect(ssl);
	if (rc == 1) {
		f->f_un.f_forw.f_tls_handshake = 0;
		NOTE("TLS handshake completed for %s", f->f_un.f_forw.f_hname);

		/* Verify certificate after successful handshake */
		if (f->f_un.f_forw.f_tls_verify == TLS_VERIFY_FINGERPRINT) {
			if (tls_verify_fingerprint(ssl, f->f_un.f_forw.f_tls_fingerprint) < 0) {
				ERRX("TLS fingerprint verification failed for %s",
				     f->f_un.f_forw.f_hname);
				SSL_free(ssl);
				f->f_un.f_forw.f_ssl = NULL;
				return -1;
			}
		} else if (f->f_un.f_forw.f_tls_verify == TLS_VERIFY_HOSTNAME) {
			if (tls_verify_hostname(ssl, f->f_un.f_forw.f_hname) < 0) {
				ERRX("TLS hostname verification failed for %s",
				     f->f_un.f_forw.f_hname);
				SSL_free(ssl);
				f->f_un.f_forw.f_ssl = NULL;
				return -1;
			}
		}
		return 0;
	}

	err = SSL_get_error(ssl, rc);
	if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
		return 1; /* Handshake in progress */
	}

	/* Log more details about the SSL error */
	if (err == SSL_ERROR_SYSCALL) {
		if (errno)
			ERR("TLS SSL_connect(%s)", f->f_un.f_forw.f_hname);
		else
			ERRX("TLS SSL_connect(%s): connection closed", f->f_un.f_forw.f_hname);
	} else if (err == SSL_ERROR_SSL) {
		tls_log_errors("SSL_connect");
	} else {
		ERRX("TLS SSL_connect(%s): error %d", f->f_un.f_forw.f_hname, err);
	}

	SSL_free(ssl);
	f->f_un.f_forw.f_ssl = NULL;
	f->f_un.f_forw.f_tls_handshake = 0;
	return -1;
}

int tls_connect_continue(struct filed *f)
{
	int rc, err;

	if (!f->f_un.f_forw.f_ssl || !f->f_un.f_forw.f_tls_handshake)
		return -1;

	rc = SSL_connect(f->f_un.f_forw.f_ssl);
	if (rc == 1) {
		f->f_un.f_forw.f_tls_handshake = 0;

		/* Verify certificate after successful handshake */
		if (f->f_un.f_forw.f_tls_verify == TLS_VERIFY_FINGERPRINT) {
			if (tls_verify_fingerprint(f->f_un.f_forw.f_ssl,
						   f->f_un.f_forw.f_tls_fingerprint) < 0) {
				ERRX("TLS fingerprint verification failed for %s",
				     f->f_un.f_forw.f_hname);
				return -1;
			}
		} else if (f->f_un.f_forw.f_tls_verify == TLS_VERIFY_HOSTNAME) {
			if (tls_verify_hostname(f->f_un.f_forw.f_ssl,
						f->f_un.f_forw.f_hname) < 0) {
				ERRX("TLS hostname verification failed for %s",
				     f->f_un.f_forw.f_hname);
				return -1;
			}
		}
		return 0;
	}

	err = SSL_get_error(f->f_un.f_forw.f_ssl, rc);
	if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
		return 1; /* Still in progress */
	}

	tls_log_errors("SSL_connect continue");
	return -1;
}

ssize_t tls_read(struct tcp_conn *tc, void *buf, size_t len)
{
	int rc, err;

	if (!tc->tc_ssl) {
		errno = EINVAL;
		return -1;
	}

	/* Handle handshake continuation */
	if (tc->tc_tls_handshake) {
		rc = tls_accept_continue(tc);
		if (rc != 0) {
			errno = EAGAIN;
			return -1;
		}
	}

	rc = SSL_read(tc->tc_ssl, buf, len);
	if (rc > 0)
		return rc;

	err = SSL_get_error(tc->tc_ssl, rc);
	if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
		errno = EAGAIN;
		return -1;
	}

	if (err == SSL_ERROR_ZERO_RETURN)
		return 0; /* Clean shutdown */

	tls_log_errors("SSL_read");
	errno = EIO;
	return -1;
}

ssize_t tls_write(struct filed *f, const void *buf, size_t len)
{
	int rc, err;

	if (!f->f_un.f_forw.f_ssl) {
		errno = EINVAL;
		return -1;
	}

	/* Handle handshake continuation */
	if (f->f_un.f_forw.f_tls_handshake) {
		rc = tls_connect_continue(f);
		if (rc != 0) {
			errno = EAGAIN;
			return -1;
		}
	}

	rc = SSL_write(f->f_un.f_forw.f_ssl, buf, len);
	if (rc > 0)
		return rc;

	err = SSL_get_error(f->f_un.f_forw.f_ssl, rc);
	if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
		errno = EAGAIN;
		return -1;
	}

	tls_log_errors("SSL_write");
	errno = EIO;
	return -1;
}

void tls_conn_close(struct tcp_conn *tc)
{
	if (tc->tc_ssl) {
		SSL_shutdown(tc->tc_ssl);
		SSL_free(tc->tc_ssl);
		tc->tc_ssl = NULL;
	}
	tc->tc_tls_handshake = 0;
}

void tls_forw_close(struct filed *f)
{
	if (f->f_un.f_forw.f_ssl) {
		SSL_shutdown(f->f_un.f_forw.f_ssl);
		SSL_free(f->f_un.f_forw.f_ssl);
		f->f_un.f_forw.f_ssl = NULL;
	}
	f->f_un.f_forw.f_tls_handshake = 0;
}

int tls_verify_fingerprint(SSL *ssl, const char *expected)
{
	X509 *cert;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int mdlen;
	char fingerprint[EVP_MAX_MD_SIZE * 3 + 8];
	const char *p;
	int i;

	if (!expected || !*expected)
		return -1;

	cert = SSL_get_peer_certificate(ssl);
	if (!cert) {
		ERRX("TLS: no peer certificate for fingerprint verification");
		return -1;
	}

	/* Compute SHA-256 fingerprint */
	if (X509_digest(cert, EVP_sha256(), md, &mdlen) != 1) {
		X509_free(cert);
		tls_log_errors("X509_digest");
		return -1;
	}
	X509_free(cert);

	/* Format as "SHA256:xx:xx:..." */
	strcpy(fingerprint, "SHA256:");
	for (i = 0; i < (int)mdlen; i++) {
		sprintf(fingerprint + 7 + i * 3, "%02X%s",
			md[i], i < (int)mdlen - 1 ? ":" : "");
	}

	/* Compare (skip "SHA256:" prefix in expected if present) */
	p = expected;
	if (!strncasecmp(p, "SHA256:", 7))
		p += 7;

	if (strcasecmp(fingerprint + 7, p) == 0)
		return 0;

	ERRX("TLS fingerprint mismatch: got %s, expected %s", fingerprint, expected);
	return -1;
}

int tls_verify_hostname(SSL *ssl, const char *hostname)
{
	X509 *cert;
	int rc;

	if (!hostname || !*hostname)
		return -1;

	cert = SSL_get_peer_certificate(ssl);
	if (!cert) {
		ERRX("TLS: no peer certificate for hostname verification");
		return -1;
	}

	/* Use OpenSSL's hostname verification */
	rc = X509_check_host(cert, hostname, strlen(hostname), 0, NULL);
	X509_free(cert);

	if (rc == 1)
		return 0;

	ERRX("TLS hostname verification failed for '%s'", hostname);
	return -1;
}

#endif /* HAVE_OPENSSL */
