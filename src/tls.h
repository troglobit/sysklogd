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
 * This module provides TLS-encrypted syslog transport, building on the
 * existing TCP infrastructure (RFC 6587) and reusing the OpenSSL integration
 * from RFC 5848 signing.
 *
 * Key RFC 5425 requirements:
 * - TLS 1.2 minimum
 * - Port 6514 designated for syslog-tls
 * - Certificate validation: chain, fingerprint, or hostname matching
 * - Optional mutual authentication (client certificates)
 */

#ifndef SYSKLOGD_TLS_H_
#define SYSKLOGD_TLS_H_

#include "config.h"

#ifdef HAVE_OPENSSL

#include <openssl/ssl.h>

/* TLS verification modes */
#define TLS_VERIFY_OFF        0  /* No verification (testing only) */
#define TLS_VERIFY_OPTIONAL   1  /* Verify if cert presented */
#define TLS_VERIFY_REQUIRED   2  /* Require valid cert */
#define TLS_VERIFY_FINGERPRINT 3 /* Verify by fingerprint */
#define TLS_VERIFY_HOSTNAME   4  /* Verify hostname in cert */

/* Forward declarations */
struct tcp_conn;
struct filed;

/*
 * Initialize TLS subsystem.
 * Creates SSL_CTX for both server and client modes.
 * Returns 0 on success, -1 on error.
 */
int     tls_init(void);

/*
 * Shutdown TLS subsystem.
 * Frees SSL_CTX and cleans up OpenSSL state.
 */
void    tls_exit(void);

/*
 * Configure TLS with certificates and options.
 * Must be called before tls_init().
 * Returns 0 on success, -1 on error.
 */
int     tls_config(const char *keyfile, const char *certfile,
                   const char *cafile, const char *capath, const char *verify);

/*
 * Check if TLS is configured and available.
 * Returns non-zero if TLS can be used.
 */
int     tls_enabled(void);

/*
 * Accept a TLS connection on a listening socket.
 * Wraps an accepted TCP connection with TLS.
 * Returns 0 on success, -1 on error, 1 if handshake in progress.
 */
int     tls_accept(struct tcp_conn *tc);

/*
 * Continue TLS handshake for accept.
 * Called when socket becomes readable during handshake.
 * Returns 0 on success, -1 on error, 1 if still in progress.
 */
int     tls_accept_continue(struct tcp_conn *tc);

/*
 * Initiate a TLS connection to a remote server.
 * Wraps an existing TCP connection with TLS.
 * Returns 0 on success, -1 on error, 1 if handshake in progress.
 */
int     tls_connect(struct filed *f);

/*
 * Continue TLS handshake for connect.
 * Called when socket becomes writable during handshake.
 * Returns 0 on success, -1 on error, 1 if still in progress.
 */
int     tls_connect_continue(struct filed *f);

/*
 * Read data from a TLS connection.
 * Returns bytes read, 0 on EOF, -1 on error.
 * Sets errno to EAGAIN if would block.
 */
ssize_t tls_read(struct tcp_conn *tc, void *buf, size_t len);

/*
 * Write data to a TLS connection.
 * Returns bytes written, -1 on error.
 * Sets errno to EAGAIN if would block.
 */
ssize_t tls_write(struct filed *f, const void *buf, size_t len);

/*
 * Close TLS connection for receive side.
 * Sends close_notify and frees SSL state.
 */
void    tls_conn_close(struct tcp_conn *tc);

/*
 * Close TLS connection for forwarding side.
 * Sends close_notify and frees SSL state.
 */
void    tls_forw_close(struct filed *f);

/*
 * Verify server certificate by fingerprint.
 * Expected format: "SHA256:xxxx..." (hex-encoded)
 * Returns 0 on match, -1 on mismatch or error.
 */
int     tls_verify_fingerprint(SSL *ssl, const char *expected);

/*
 * Verify server certificate hostname.
 * Checks CN and SAN fields.
 * Returns 0 on match, -1 on mismatch or error.
 */
int     tls_verify_hostname(SSL *ssl, const char *hostname);

#else /* !HAVE_OPENSSL */

/* Stub macros when TLS not available */
#define TLS_VERIFY_OFF        0
#define TLS_VERIFY_OPTIONAL   1
#define TLS_VERIFY_REQUIRED   2
#define TLS_VERIFY_FINGERPRINT 3
#define TLS_VERIFY_HOSTNAME   4

#define tls_init()                   (0)
#define tls_exit()                   do {} while(0)
#define tls_config(k,c,a,p,v)        (0)
#define tls_enabled()                (0)
#define tls_accept(tc)               (-1)
#define tls_accept_continue(tc)      (-1)
#define tls_connect(f)               (-1)
#define tls_connect_continue(f)      (-1)
#define tls_read(tc, buf, len)       (-1)
#define tls_write(f, buf, len)       (-1)
#define tls_conn_close(tc)           do {} while(0)
#define tls_forw_close(f)            do {} while(0)
#define tls_verify_fingerprint(s,e)  (-1)
#define tls_verify_hostname(s,h)     (-1)

#endif /* HAVE_OPENSSL */
#endif /* SYSKLOGD_TLS_H_ */
