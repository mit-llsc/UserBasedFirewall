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
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>

#ifdef DEBUG_LOG
	#include <netinet/in.h>
	#include <arpa/inet.h>
#endif

#include "SyncAskIdent2.h"

int ident2_sock = -1;

#ifdef DEBUG_LOG
void AsciiDumpBuffer(FILE* iStream, uint8* buf, unsigned int size) {
	for (unsigned int x=0; x<size; x++) {
		if (x && (x % 8) == 0)
			fprintf(iStream, " ");
		if (buf[x] >= 32 && buf[x] <= 126)
			fprintf(iStream, "%c", buf[x]);
		else
			fprintf(iStream, ".");
	}
}
void HexDumpBuffer(FILE* iStream, uint8* buf, unsigned int size, char* newlinepad) {
	unsigned int x;
	if (newlinepad)
		fprintf(iStream, "%s", newlinepad);
	for (x=0; x<size; x++) {
		if (x && (x % 16) == 0) {
			fprintf(iStream, " ");
			AsciiDumpBuffer(iStream, &buf[x-16], 16);
			fprintf(iStream, "\n");
			if (newlinepad)
				fprintf(iStream, "%s", newlinepad);
		}
		else if (x % 16 == 8)
			fprintf(iStream, "- ");
		if ((x % 16) == 0)
			fprintf(iStream, "%4u: ", x);
		fprintf(iStream, "%02X ", buf[x]);
	}
	unsigned int tmp = 16 - (size%16);
	if (tmp != 16) {
		for (x=0; x<tmp; x++) {
			if (x == 7)
				fprintf(iStream, "  ");
			fprintf(iStream, "   ");
		}
	}
	tmp = size % 16;
	if (tmp == 0)
		tmp = 16;
	fprintf(iStream, " ");
	AsciiDumpBuffer(iStream, &buf[size - tmp], tmp);
	fprintf(iStream, "\n");
}
#endif

int InitSyncIdent2d() {
	sigset_t sig_set;
	// Block the SIGIO signal so we can catch pending SIGIOs later with sigtimedwait
	if (sigemptyset(&sig_set) != 0) {
		fprintf(stderr, "sigemptyset() failed. errno=%i (%s)\n", errno, strerror(errno));
		return 0;
	}
	if (sigaddset(&sig_set, SIGIO) != 0) {
		fprintf(stderr, "sigaddset(SIGIO) failed. errno=%i (%s)\n", errno, strerror(errno));
		return 0;
	}
	if (sigprocmask(SIG_BLOCK, &sig_set, NULL) != 0) {
		fprintf(stderr, "sigprocmask(SIG_BLOCK, SIGIO) failed. errno=%i (%s)\n", errno, strerror(errno));
		return 0;
	}
	return 1;
}

int ConnectIdent2Sock() {
	// try connection to ident2d
	struct sockaddr_un addr;

	if ((ident2_sock = socket(PF_UNIX, SOCK_SEQPACKET, 0)) < 0) {
		fprintf(stderr, "Error: socket() for ident2_sock failed. errno=%i (%s)\n", errno, strerror(errno));
		ident2_sock = -1;
		return 0;
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, IDENT2_SOCKNAME, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path)-1] = '\0';

	if (connect( ident2_sock, (struct sockaddr *) &addr, sizeof(addr) ) != 0) {
		fprintf(stderr, "Error: connect(ident2_sock) failed. errno=%i (%s)\n", errno, strerror(errno));
		close(ident2_sock);
		ident2_sock = -1;
		return 0;
	}

	// set nonblocking and SIGIO on our ident2d socket
	if (fcntl(ident2_sock, F_SETOWN, getpid()) < 0) {
		fprintf(stderr, "fcntl(ident2_sock, F_SETOWN) failed. errno=%i (%s)\n", errno, strerror(errno));
		return -1;
	}
	if (fcntl(ident2_sock, F_SETFL, O_NONBLOCK | O_ASYNC) < 0) {
		fprintf(stderr, "fcntl(ident2_sock, O_NONBLOCK | O_ASYNC) failed. errno=%i (%s)\n", errno, strerror(errno));
		return -1;
	}

	return 1;
}

// returns response, or NULL on error and sets errno
struct query_sock_response * SyncAskIdent2(uint8 LocalOrRemote, uint8 flags, uint8 ip_version, uint8 protocol, void* lIP, uint16 lPort, void* rIP, uint16 rPort, uint32 tcp_states) {
	static uint64 static_queryID = 0;
	static uint8 buffer[16384];

	struct msghdr msg_s, msg_r;
	struct iovec iov_s[2], iov_r[2];
	char opcode_s, opcode_r;
	struct query_sock qs;
	int rv;
	struct timespec orig, now, sig_timeout, elapsed;
	sigset_t sig_set;
#ifdef DEBUG_LOG
	char ip_str[INET6_ADDRSTRLEN];
#endif
	uint32 num_tried = 0;


	if (ident2_sock == -1) {
		if (ConnectIdent2Sock() != 1) {
			errno = -ENOTCONN;
			return NULL;
		}
	}

	if (LocalOrRemote == IDENT2_LOCAL)
		opcode_s = OP_QueryLocalConnection;
	else if (LocalOrRemote == IDENT2_REMOTE)
		opcode_s = OP_QueryRemoteConnection;
	else {
		errno = -EINVAL;
		return NULL;
	}

	memset(&qs, 0, sizeof(qs));
	qs.queryid = ++static_queryID;
	qs.flags = 0;
	qs.flags = flags;
	qs.ip_version = ip_version;
	qs.protocol = protocol;
	qs.tcpstates = tcp_states;		// TCP Flags for states to match
	if (lIP)
		memcpy(qs.local_ip, lIP, ip_version == 4 ? 4 : 16);
	qs.local_port = lPort;
	if (rIP)
		memcpy(qs.remote_ip, rIP, ip_version == 4 ? 4 : 16);;
	qs.remote_port = rPort;

#ifdef DEBUG_LOG
	fprintf(stderr, "Sending ident2d question:\n");
	fprintf(stderr, "opcode: %s\n", opcode_s == OP_QueryLocalConnection ? "OP_QueryLocalConnection" : "OP_QueryRemoteConnection");
	fprintf(stderr, "queryid: 0x%016lx\n", qs.queryid);
	fprintf(stderr, "flags: %i\n", qs.flags);
	fprintf(stderr, "ip_version: %i\n", qs.ip_version);
	fprintf(stderr, "protocol: %i\n", qs.protocol);
	fprintf(stderr, "tcpstates: %i (0x%08x)\n", qs.tcpstates, qs.tcpstates);
	fprintf(stderr, "local_ip: %s\n", inet_ntop(ip_version == 4 ? AF_INET : AF_INET6, qs.local_ip, ip_str, sizeof(ip_str)));
	fprintf(stderr, "local_port: %i\n", qs.local_port);
	fprintf(stderr, "remote_ip: %s\n", inet_ntop(ip_version == 4 ? AF_INET : AF_INET6, qs.remote_ip, ip_str, sizeof(ip_str)));
	fprintf(stderr, "remote_port: %i\n", qs.remote_port);
	HexDumpBuffer(stderr, (uint8*) &qs, sizeof(qs), "");
	fprintf(stderr, "---------------------------\n");
#endif

	iov_s[0].iov_base = &opcode_s;
	iov_s[0].iov_len = 1;
	iov_s[1].iov_base = &qs;
	iov_s[1].iov_len = sizeof(qs);

	memset(&msg_s, 0, sizeof(msg_s));
	msg_s.msg_iov = iov_s;
	msg_s.msg_iovlen = 2;

	if (sendmsg(ident2_sock, &msg_s, 0) == -1) {
		fprintf(stderr, "AskIdent2: Error: sendmsg(ident2_sock) failed, closing socket. errno=%i (%s)\n", errno, strerror(errno));
		close(ident2_sock);
		ident2_sock = -1;
		errno = ECOMM;
		return NULL;
	}

	if (sigemptyset(&sig_set) != 0) {
		fprintf(stderr, "sigemptyset() failed. errno=%i (%s)\n", errno, strerror(errno));
		return NULL;
	}
	if (sigaddset(&sig_set, SIGIO) != 0) {
		fprintf(stderr, "sigaddset(SIGIO) failed. errno=%i (%s)\n", errno, strerror(errno));
		return NULL;
	}

	clock_gettime(CLOCK_MONOTONIC, &orig);
	sig_timeout.tv_sec = SYNCIDENT2_WAIT_SEC;
	sig_timeout.tv_nsec = SYNCIDENT2_WAIT_NSEC;
	while (1) {
		if (sig_timeout.tv_sec == 0 && sig_timeout.tv_nsec == 0) // signal from wrong queryID loop that it had no time remaining on current retry
			rv = EAGAIN;
		else
			rv = sigtimedwait(&sig_set, NULL, &sig_timeout); // sleep until we get a SIGIO notiication, or 150ms, or interrupted by some other signal handler, whichever comes first
		if (rv < 0 || rv == EAGAIN) {
			// EAGAIN == we timed out
			num_tried++;
			if (num_tried >= SYNCIDENT2_NUM_RETRIES) {
				errno = ETIMEDOUT;
				return NULL;
			}
			if (sendmsg(ident2_sock, &msg_s, 0) == -1) {
				fprintf(stderr, "AskIdent2: Error: sendmsg(ident2_sock) failed, closing socket. errno=%i (%s)\n", errno, strerror(errno));
				close(ident2_sock);
				ident2_sock = -1;
				errno = ECOMM;
				return NULL;
			}
			clock_gettime(CLOCK_MONOTONIC, &orig);
			sig_timeout.tv_sec = SYNCIDENT2_WAIT_SEC;
			sig_timeout.tv_nsec = SYNCIDENT2_WAIT_NSEC;
			continue;
		}
		if (rv < 0 || rv != SIGIO) {
			// EINTR == some other signal handler triggered
			// but all the same... we expect no other signal handlers and timeout == error for us
			return NULL;
		}

		//memset(buffer, 0, sizeof(buffer));
		iov_r[0].iov_base = &opcode_r;
		iov_r[0].iov_len = sizeof(opcode_r);
		iov_r[1].iov_base = buffer;
		iov_r[1].iov_len = sizeof(buffer);
	
		memset(&msg_r, 0, sizeof(msg_r));
		msg_r.msg_iov = iov_r;
		msg_r.msg_iovlen = 2;
	
		rv = recvmsg(ident2_sock, &msg_r, 0);
		if (rv <= 0) {
			if (rv == 0 || errno == ECONNRESET) {
				fprintf(stderr, "Warning: Lost connection to ident2d\n");
				close(ident2_sock);
				ident2_sock = -1;
				errno = ECONNRESET;
				return NULL;
			}
			fprintf(stderr, "recvmsg(ident2_sock) errored. errno=%i (%s)\n", errno, strerror(errno));
			return NULL;
		}
		else if ( rv < (sizeof(struct query_sock_response) + sizeof(opcode_r)) ) {
			fprintf(stderr, "Warning: recvmsg(ident2_sock) returned message too short to be useful. Dropping ident2d connection. rv=%i\n", rv);
			close(ident2_sock);
			ident2_sock = -1;
			errno = ENODATA;
			return NULL;
		}
		else if (opcode_r != OP_QueryRemoteConnectionResponse) {
			fprintf(stderr, "Warning: recvmsg(ident2_sock) returned unexpected opcode. Dropping ident2d connection. opcode=%i\n", opcode_r);
			close(ident2_sock);
			ident2_sock = -1;
			errno = EPROTO;
			return NULL;
		}

		// got actionable message
		struct query_sock_response *qsr = (struct query_sock_response *) &buffer[0];

#ifdef DEBUG_LOG
		fprintf(stderr, "Got ident2d response: %s\n", opcode_r == OP_QueryLocalConnectionResponse ? "OP_QueryLocalConnectionResponse" : "OP_QueryRemoteConnectionResponse");
		fprintf(stderr, "queryid: 0x%016lx\n", qsr->queryid);
		fprintf(stderr, "flags: %i\n", qsr->flags);
		fprintf(stderr, "pid: %i\n", qsr->pid);
		fprintf(stderr, "uid: %i\n", qsr->uid);
		fprintf(stderr, "gid: %i\n", qsr->gid);
		fprintf(stderr, "nsgids: %i\n", qsr->nsgids);
		for (int x=0; x<qsr->nsgids; x++)
			fprintf(stderr, "sgids[%i]: %i\n", x, qsr->sgids[x]);
		HexDumpBuffer(stderr, (uint8*) qsr, sizeof(struct query_sock_response), "");
		fprintf(stderr, "---------------------------\n");
#endif

		if (qsr->queryid != static_queryID) {
			// wrong packet (late reply from an earlier question), skip... but only wait the remainder of our time
#ifdef DEBUG_LOG
			fprintf(stderr, "Notice: Got stale reply (got: 0x%016lx, expected: 0x%016lx)\n", qsr->queryid, static_queryID);
#endif
			clock_gettime(CLOCK_MONOTONIC, &now);
			elapsed.tv_sec = now.tv_sec - orig.tv_sec;
			if (now.tv_nsec < orig.tv_nsec) {
				elapsed.tv_sec--;
				elapsed.tv_nsec = 1000000000 + (now.tv_nsec - orig.tv_nsec);
			}
			else
				elapsed.tv_nsec = now.tv_nsec - orig.tv_nsec;

			if (elapsed.tv_sec > SYNCIDENT2_WAIT_SEC || (elapsed.tv_sec == SYNCIDENT2_WAIT_SEC && elapsed.tv_nsec >= SYNCIDENT2_WAIT_NSEC)) {
				sig_timeout.tv_sec = 0;
				sig_timeout.tv_nsec = 0;
				continue;
			}

			sig_timeout.tv_sec = SYNCIDENT2_WAIT_SEC - elapsed.tv_sec;
			if (elapsed.tv_nsec > SYNCIDENT2_WAIT_NSEC) {
				sig_timeout.tv_sec--;
				sig_timeout.tv_nsec = 1000000000 - (elapsed.tv_nsec - SYNCIDENT2_WAIT_NSEC);
			}
			else
				sig_timeout.tv_nsec = SYNCIDENT2_WAIT_NSEC - elapsed.tv_nsec;

			continue;
		}
			
		return qsr;
	} // while
	return NULL;
}
