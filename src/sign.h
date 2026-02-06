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
 * This module provides cryptographic signing of syslog messages using
 * OpenSSL. It is optional and only compiled when --with-openssl is used.
 */

#ifndef SYSKLOGD_SIGN_H_
#define SYSKLOGD_SIGN_H_

#include "config.h"

#ifdef HAVE_OPENSSL

/* Signature Group modes per RFC 5848 Section 4.2.5 */
#define SIGN_SG_GLOBAL   0  /* Single group for all messages */
#define SIGN_SG_PRIORITY 1  /* One group per priority (192 groups) */
#define SIGN_SG_RANGE    2  /* Priority ranges with delimiters */
#define SIGN_SG_DEST     3  /* One group per destination (NetBSD ext) */

/* Maximum hash block count per signature block (RFC 5848 Section 5.1) */
#define SIGN_MAX_HASHES  100

/* Signature block interval in seconds */
#define SIGN_BLOCK_INTERVAL 30

/* Certificate block rekey interval in hours (RFC 5848 Section 5.2.1) */
#define SIGN_CERT_REKEY_HOURS 3

/* Forward declarations */
struct buf_msg;
struct filed;

/*
 * Initialize signing subsystem.
 * Called from syslogd init() after configuration is parsed.
 * Returns 0 on success, -1 on error.
 */
int  sign_init(void);

/*
 * Shutdown signing subsystem.
 * Called from syslogd die().
 */
void sign_exit(void);

/*
 * Apply configuration from cfkey variables.
 * Called after config file is parsed.
 * Returns 0 on success, -1 on error.
 */
int  sign_config(const char *sg_str, const char *delim_str,
		 const char *keyfile, const char *certfile);

/*
 * Check if signing is enabled.
 * Returns non-zero if signing is configured and keys loaded.
 */
int  sign_enabled(void);

/*
 * Called for each message during logmsg() to compute and store hash.
 * Must be called before message is distributed to filed entries.
 */
void sign_msg_hash(struct buf_msg *msg, struct filed *f);

/*
 * Timer callback to send signature blocks.
 * Registered with timer_add() during sign_init().
 */
void sign_send_blocks(void *arg);

/*
 * Send certificate block.
 * Called at startup and periodically.
 */
void sign_send_cert_block(void);

#else /* !HAVE_OPENSSL */

/* Stub macros when signing not available */
#define sign_init()                      (0)
#define sign_exit()                      do {} while(0)
#define sign_config(s, d, k, c)          (0)
#define sign_enabled()                   (0)
#define sign_msg_hash(msg, f)            do {} while(0)
#define sign_send_blocks(arg)            do {} while(0)
#define sign_send_cert_block()           do {} while(0)

#endif /* HAVE_OPENSSL */
#endif /* SYSKLOGD_SIGN_H_ */
