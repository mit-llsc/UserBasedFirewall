/*
 * DISTRIBUTION STATEMENT A. Approved for public release. Distribution is unlimited.
 *
 * This material is based upon work supported by the Department of the Air Force under
 * Air Force Contract No. FA8702-15-D-0001. Any opinions, findings, conclusions or
 * recommendations expressed in this material are those of the author(s) and do not
 * necessarily reflect the views of the Department of the Air Force.
 *
 * (c) 2024 Massachusetts Institute of Technology.
 *
 * The software/firmware is provided to you on an As-Is basis
 *
 * Delivered to the U.S. Government with Unlimited Rights, as defined in DFARS
 * Part 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice,
 * U.S. Government rights in this work are defined by DFARS 252.227-7013 or
 * DFARS 252.227-7014 as detailed above. Use of this work other than as specifically
 * authorized by the U.S. Government may violate any copyrights that exist in this work.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#ifndef SOCK_TYPE_MASK
	// see kernel:/include/linux/net.h
	#define SOCK_TYPE_MASK 0xf
#endif

typedef u_int8_t uint8;
typedef u_int16_t uint16;
typedef u_int32_t uint32;
typedef u_int64_t uint64;

#include "ident2d_api.h"
//#define DEBUG_LOG

int socket(int domain, int type, int protocol) {
	static int (*real_socket)(int, int, int) = NULL;
	int newsock, ident2_sock = -1;
	struct sockaddr_un addr;
	struct iovec iov;
	struct msghdr msg;

	if (!real_socket)
		real_socket = dlsym(RTLD_NEXT, "socket");
	newsock = real_socket(domain, type, protocol);
	if (newsock < 0)
		return newsock;
	if (!(domain == AF_INET || domain == AF_INET6))
		return newsock;
	if (!(
		((type & SOCK_TYPE_MASK) == SOCK_STREAM && (protocol == 0 || protocol == IPPROTO_TCP))
		|| ((type & SOCK_TYPE_MASK) == SOCK_DGRAM && (protocol == 0 || protocol == IPPROTO_UDP))
		))
		return newsock;

	// Ok, we have a socket we can work with...
	if ((ident2_sock = real_socket(PF_UNIX, SOCK_SEQPACKET, 0)) < 0) {
		#ifdef DEBUG_LOG
			fprintf(stderr, "Error: socket() for ident2_sock failed. errno=%i (%s)\n", errno, strerror(errno));
		#endif
		goto cleanup;
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, IDENT2PRECACHE_SOCKNAME, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path)-1] = '\0';

	if (connect( ident2_sock, (struct sockaddr *) &addr, sizeof(addr) ) != 0) {
		#ifdef DEBUG_LOG
			fprintf(stderr, "Error: connect(ident2_sock) failed. errno=%i (%s)\n", errno, strerror(errno));
		#endif
		goto cleanup;
	}

	iov.iov_base = &newsock;
	iov.iov_len = sizeof(int);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(ident2_sock, &msg, 0) == -1) {
		#ifdef DEBUG_LOG
			fprintf(stderr, "Error: sendmsg(ident2_sock) failed. errno=%i (%s)\n", errno, strerror(errno));
		#endif
		goto cleanup;
	}

cleanup:
	if (ident2_sock != -1)
		close(ident2_sock);
	ident2_sock = -1;

	return newsock;
}
