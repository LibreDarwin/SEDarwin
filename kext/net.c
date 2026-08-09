/*-
 * SEDarwin policy kext - network access-control hooks.
 *
 * M0 stage: observational. socket(2) creation and connect/listen are traced;
 * the addresses are formatted without any mbuf/packet access, straight from
 * the sockaddr the kernel hands over (guaranteed valid for the socket domain).
 */

#include "kernel.h"
#include <netinet/in.h>

int
sebsd_socket_check_create(kauth_cred_t cred, int domain, int type,
    int protocol)
{
	char pname[MAXCOMLEN + 1];

	if (!sebsd_tracing()) {
		return 0;
	}
	sebsd_cur_name(pname, sizeof(pname));
	sebsd_log_debug("socket create: %s pid=%d domain=%d type=%d proto=%d",
	    pname, sebsd_cur_pid(), domain, type, protocol);
	return 0;
}

int
sebsd_socket_check_connect(kauth_cred_t cred, socket_t so,
    struct label *socklabel, struct sockaddr *addr)
{
	char pname[MAXCOMLEN + 1];
	char host[64];

	(void)so;
	(void)socklabel;

	if (!sebsd_tracing() || addr == NULL) {
		return 0;
	}

	sebsd_cur_name(pname, sizeof(pname));
	host[0] = '\0';

	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)(void *)addr;
		const uint8_t *a = (const uint8_t *)&sin->sin_addr;
		snprintf(host, sizeof(host), "%u.%u.%u.%u:%u", a[0], a[1], a[2],
		    a[3], ntohs(sin->sin_port));
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(void *)addr;
		const uint8_t *a = sin6->sin6_addr.__u6_addr.__u6_addr8;
		snprintf(host, sizeof(host),
		    "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
		    "%02x%02x:%02x%02x",
		    a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
		    a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
		break;
	}
	case AF_UNIX:
		strlcpy(host, "<unix>", sizeof(host));
		break;
	default:
		snprintf(host, sizeof(host), "af=%d", addr->sa_family);
		break;
	}

	sebsd_log_debug("connect: %s pid=%d -> %s uid=%d", pname, sebsd_cur_pid(),
	    host, kauth_cred_getuid(cred));
	return 0;
}

int
sebsd_socket_check_listen(kauth_cred_t cred, socket_t so,
    struct label *socklabel)
{
	char pname[MAXCOMLEN + 1];

	(void)so;
	(void)socklabel;

	if (!sebsd_tracing()) {
		return 0;
	}
	sebsd_cur_name(pname, sizeof(pname));
	sebsd_log_debug("listen: %s pid=%d uid=%d", pname, sebsd_cur_pid(),
	    kauth_cred_getuid(cred));
	return 0;
}
