/*-
 * SPDX-License-Identifier: Unlicense
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Forward log messages to a multicast group, bypassing the local syslogd.
 * Pointing log_host at a sockaddr makes libsyslog send() there directly;
 * when that address is multicast, log_iface and log_ttl select the
 * outgoing interface and IP TTL.
 *
 * Receive side, for testing:
 *   socat UDP4-RECVFROM:514,ip-add-membership=239.0.0.1:eth0,fork -
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>		/* NULL (used by SYSLOG_DATA_INIT) */
#include <syslog/syslog.h>

int main(void)
{
	struct syslog_data sd = SYSLOG_DATA_INIT;
	struct sockaddr_in group = { 0 };

	group.sin_family = AF_INET;
	group.sin_port   = htons(514);
	inet_pton(AF_INET, "239.0.0.1", &group.sin_addr);

	/* Direct delivery to this address instead of the local /dev/log. */
	sd.log_host  = &group;

	/* Multicast knobs: outgoing interface by name, and the IP TTL. */
	sd.log_iface = "eth0";	/* NULL = kernel default route */
	sd.log_ttl   = 4;	/* 1 = stay on-link (default) */

	openlog_r("multicast", LOG_PID, LOG_LOCAL0, &sd);
	syslog_r(LOG_NOTICE, &sd, "broadcasting to 239.0.0.1:514");
	closelog_r(&sd);

	return 0;
}
