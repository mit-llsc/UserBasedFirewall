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
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <dirent.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <libnfnetlink/libnfnetlink.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <linux/inet_diag.h>

#include "ident2d.h"
#include "tcp_states.h"

struct inode_cache_entry {
	struct inode_cache_entry *next;
	uint64	ts;
	uint32	inode;
	uid_t	uid;
	pid_t	pid;
	int 	fdno;
	uint8	ip_version;
	uint8	protocol;
	uint32	ip[4];
	uint16	port;
};

int netlink_sock = -1;
pthread_mutex_t netlink_mutex; // hold for accessing netlink_sock
pthread_mutex_t findsock_cache_mutex; // hold for accessing netlink_sock
struct inode_cache_entry *inode_cache_head = NULL;
#define INODE_NEGCACHE_TIMEOUT         250 // cache negative entries for a quarter second from when added
#define INODE_CACHE_DROP_TIMEOUT     15000 // cache hits for 15 seconds from adding or last use

int open_netlink_socket() {
	if ((netlink_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_INET_DIAG)) < 0)
		return -1;
	if (pthread_mutex_init(&netlink_mutex, NULL) != 0) {
		logit("Error: pthread_mutex_init for netlink_mutex failed. errno=%i (%s)\n", errno, strerror(errno));
		return -1;
	}
	return 0;
}

void close_netlink_socket() {
	if (netlink_sock == -1)
		return;
	close(netlink_sock);
	netlink_sock = -1;

	if (pthread_mutex_destroy(&netlink_mutex) != 0)
		logit("Warning: pthread_mutex_destroy for netlink_mutex failed. errno=%i (%s)\n", errno, strerror(errno));
}

#ifdef FINDSOCKET_DEBUG
static const char* tcp_get_state_name(int state) {
	static const char* tcp_states_map[]={
		[TCP_ESTABLISHED] = "ESTABLISHED",
		[TCP_SYN_SENT] = "SYN-SENT",
		[TCP_SYN_RECV] = "SYN-RECV",
		[TCP_FIN_WAIT1] = "FIN-WAIT-1",
		[TCP_FIN_WAIT2] = "FIN-WAIT-2",
		[TCP_TIME_WAIT] = "TIME-WAIT",
		[TCP_CLOSE] = "CLOSE",
		[TCP_CLOSE_WAIT] = "CLOSE-WAIT",
		[TCP_LAST_ACK] = "LAST-ACK",
		[TCP_LISTEN] = "LISTEN",
		[TCP_CLOSING] = "CLOSING"
	};
	if (state < 0 || state >= TCP_MAX_STATES)
		return NULL;
	return tcp_states_map[state];
}
#endif

// Return value: 0=no, 1=yes; if no oipv4 is unchanged. oipv4 is optional and may be NULL.
int IsIPv4inIPv6(void *IP6, uint32 *oipv4) {
	uint32 *IP6_parts = ((uint32*) IP6);
	if (IP6_parts[0] == 0 && IP6_parts[1] == 0 && IP6_parts[2] == 0 && IP6_parts[3] == 0) {
		if (oipv4)
			*oipv4 = 0;
		return 1;
	}
	if (IP6_parts[0] == 0 && IP6_parts[1] == 0 && IP6_parts[2] == htonl(0xFFFF)) {
		if (oipv4)
			*oipv4 = IP6_parts[3];
		return 1;
	}
	if (IP6_parts[0] == 0 && IP6_parts[1] == 0 && IP6_parts[2] == 0 && IP6_parts[3] == htonl(1)) {
		if (oipv4)
			*oipv4 = htonl(0x7F000001);
		return 1;
	}
	return 0;
}

#define IS_IPV6_ANYADDR(x) (memcmp(x, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) == 0)

// Find socket matching parameters specified.
// If more than one match is found, returned inode/uid is most specific
//   e.g., if there's a listning port on IPADDR_ANY and 127.0.0.1, will return for the 127.0.0.1 socket
int find_socket_tcp(uint8 in_ip_version, void* in_lip, uint16 search_lport, void* in_rip, uint16 search_rport, uint32 tcp_states, uint32* oINode, uid_t* oUID) {
	int retval = -2;
	struct msghdr msg;
	struct sockaddr_nl nladdr;
	struct nlmsghdr nlh_req;
	struct inet_diag_req req;
	char	buf[16384];
	struct iovec iov[2];
	static int seq = 1234567;
   	int num_matches = 0;
	uint32	search_lip4 = -1, search_rip4 = -1;
	void	*search_lip6 = NULL, *search_rip6 = NULL;
	uint8	search_ip_version = 0;
   	// global int netlink_sock;
#ifdef FINDSOCKET_DEBUG
	char lip_str[INET6_ADDRSTRLEN], rip_str[INET6_ADDRSTRLEN];
#endif

	if (netlink_sock == -1) {
		errno = -ENOTCONN;
		return -1;
	}

	search_ip_version = in_ip_version;
	if (in_ip_version == 6) {
		if (IsIPv4inIPv6(in_lip, &search_lip4) && IsIPv4inIPv6(in_rip, &search_rip4))
			search_ip_version = 4;
		else {
			search_lip6 = in_lip;
			search_rip6 = in_lip;
		}
	}
	else {
		search_lip4 = *((uint32*) in_lip);
		search_rip4 = *((uint32*) in_rip);
	}

	#ifdef FINDSOCKET_DEBUG
		logit("find_socket_tcp: called, acquiring mutex\n");
	#endif
	pthread_mutex_lock(&netlink_mutex);
	#ifdef FINDSOCKET_DEBUG
		logit("find_socket_tcp: mutex acquired\n");
	#endif
	seq++;

	memset(&msg, 0, sizeof(msg));
	memset(&nladdr, 0, sizeof(nladdr));
	memset(&nlh_req, 0, sizeof(nlh_req));
	memset(&req, 0, sizeof(req));
	memset(iov, 0, sizeof(iov));

	req.idiag_family = AF_INET;
	req.idiag_src_len = 4;
	req.idiag_dst_len = 4;
	//req.idiag_ext = ...; // flags to request even more info

	// Source Port = Local Port, Dst Port = Remote Port
	req.id.idiag_sport = htons(search_lport); // __be16  idiag_sport; // port#=0 == ANY
	req.id.idiag_dport = htons(search_rport); // __be16  idiag_dport;
	// request src/dst IP matching is not implemented in the kernel...
//	req.id.idiag_src[0] = search_lip; // __be32  idiag_src[4]
//	req.id.idiag_dst[0] = search_rip = ; // __be32  idiag_dst[4];
	// idiag_if is a problem. There's no "any" value unless we use "dump" mode
//	req.id.idiag_if = ; // __u32   idiag_if
	// Cookie disabled in GRSec (pointer to kernel buffer). INET_DIAG_NOCOOKIE=~0
	req.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE; //__u32   idiag_cookie[2];
	req.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;

	if (tcp_states != 0)
		req.idiag_states = tcp_states;
	else
		req.idiag_states = -1;
//		req.idiag_states = TCPF_STATES_ALL;

	nlh_req.nlmsg_len = sizeof(nlh_req) + sizeof(req);
	nlh_req.nlmsg_type = TCPDIAG_GETSOCK;
	nlh_req.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP; // NLM_F_ATOMIC
	nlh_req.nlmsg_pid = getpid();
	nlh_req.nlmsg_seq = seq;
	
	iov[0].iov_base = &nlh_req,
	iov[0].iov_len = sizeof(nlh_req);
	iov[1].iov_base = &req,
	iov[1].iov_len = sizeof(req);

	nladdr.nl_family = AF_NETLINK;
	
	msg.msg_name = (void*)&nladdr,
	msg.msg_namelen = sizeof(nladdr),
	msg.msg_iov = iov,
	msg.msg_iovlen = 2;

	#ifdef FINDSOCKET_DEBUG
		logit("find_socket_tcp: sending query to netlink...\n");
		logit("  LPort=%i, RPort=%i, TCP_States=%i%s%s%s%s%s%s%s%s%s%s%s%s\n", search_lport, search_rport, tcp_states
			, ((tcp_states & TCPF_STATES_ALL) == TCPF_STATES_ALL) ? " TCPF_STATES_ALL" : ""
			, (((tcp_states & TCPF_STATES_ALL) != TCPF_STATES_ALL) && (tcp_states & TCPF_ESTABLISHED)) ? " TCPF_ESTABLISHED" : ""
			, (((tcp_states & TCPF_STATES_ALL) != TCPF_STATES_ALL) && (tcp_states & TCPF_SYN_SENT)) ? " TCPF_SYN_SENT" : ""
			, (((tcp_states & TCPF_STATES_ALL) != TCPF_STATES_ALL) && (tcp_states & TCPF_SYN_RECV)) ? " TCPF_SYN_RECV" : ""
			, (((tcp_states & TCPF_STATES_ALL) != TCPF_STATES_ALL) && (tcp_states & TCPF_FIN_WAIT1)) ? " TCPF_FIN_WAIT1" : ""
			, (((tcp_states & TCPF_STATES_ALL) != TCPF_STATES_ALL) && (tcp_states & TCPF_FIN_WAIT2)) ? " TCPF_FIN_WAIT2" : ""
			, (((tcp_states & TCPF_STATES_ALL) != TCPF_STATES_ALL) && (tcp_states & TCPF_TIME_WAIT)) ? " TCPF_TIME_WAIT" : ""
			, (((tcp_states & TCPF_STATES_ALL) != TCPF_STATES_ALL) && (tcp_states & TCPF_CLOSE)) ? " TCPF_CLOSE" : ""
			, (((tcp_states & TCPF_STATES_ALL) != TCPF_STATES_ALL) && (tcp_states & TCPF_CLOSE_WAIT)) ? " TCPF_CLOSE_WAIT" : ""
			, (((tcp_states & TCPF_STATES_ALL) != TCPF_STATES_ALL) && (tcp_states & TCPF_LAST_ACK)) ? " TCPF_LAST_ACK" : ""
			, (((tcp_states & TCPF_STATES_ALL) != TCPF_STATES_ALL) && (tcp_states & TCPF_LISTEN)) ? " TCPF_LISTEN" : ""
			, (((tcp_states & TCPF_STATES_ALL) != TCPF_STATES_ALL) && (tcp_states & TCPF_CLOSING)) ? " TCPF_CLOSING" : ""
			);
	#endif
	if (sendmsg(netlink_sock, &msg, 0) < 0) {
		logit("find_socket_tcp: sendmsg() failed. errno=%i\n", errno);
		retval = -1;
		goto cleanup;
	}

	memset(iov, 0, sizeof(iov));
	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(buf);

	while (1) {
		int rv;
		struct nlmsghdr *nlh_resp;
	   	uint32 prev_match_lip4 = 0, prev_match_lip6[4] = { 0, 0, 0, 0 };
	   	uint8 prev_match_family = 0;

		msg.msg_name = (void*)&nladdr;
		msg.msg_namelen = sizeof(nladdr);
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = 0;

		#ifdef FINDSOCKET_DEBUG
			logit("find_socket_tcp: calling recvmsg...\n");
		#endif
		rv = recvmsg(netlink_sock, &msg, 0);
		if (rv < 0) {
			if (errno == EINTR)
				continue;
			logit("find_socket_tcp: recvmsg() failed. rv=%i, errno=%i\n", rv, errno);
			retval = -1;
			goto cleanup;
		}
		if (rv == 0) {
			logit("find_socket_tcp: EOF on netlink\n");
			retval = -1;
			goto cleanup;
		}
		#ifdef FINDSOCKET_DEBUG
			logit("find_socket_tcp: got netlink response: rv=%i\n", rv);
		#endif

		nlh_resp = (struct nlmsghdr*)buf;
		while (NLMSG_OK(nlh_resp, rv)) {
			struct inet_diag_msg *resp = NULL;
			uint16 lport, rport;

			if (nlh_resp->nlmsg_seq != seq) {
				#ifdef FINDSOCKET_DEBUG
					logit("find_socket_tcp: Got netlink message with wrong sequence number. Got: %i. Expected: %i.\n", nlh_resp->nlmsg_seq, seq);
				#endif
				goto skip_it;
			}

			if (nlh_resp->nlmsg_type == NLMSG_DONE) {
				// normal exit
				#ifdef FINDSOCKET_DEBUG
					logit("find_socket_tcp: Got netlink message NLMSG_DONE. nlh_resp->nlmsg_pid=%i, nlh_resp->nlmsg_seq=%i\n", nlh_resp->nlmsg_pid, nlh_resp->nlmsg_seq);
				#endif
				retval = num_matches;
				goto cleanup;
			}
			if (nlh_resp->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA(nlh_resp);
				if (nlh_resp->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
					errno = -EBADMSG;
					logit("find_socket_tcp: ERROR but error message truncated. nlh_resp->nlmsg_pid=%i, nlh_resp->nlmsg_seq=%i\n", nlh_resp->nlmsg_pid, nlh_resp->nlmsg_seq);
				} else {
					errno = -err->error;
					logit("find_socket_tcp: TCPDIAG answers with error. errno=%i, nlh_resp->nlmsg_pid=%i, nlh_resp->nlmsg_seq=%i\n", err->error, nlh_resp->nlmsg_pid, nlh_resp->nlmsg_seq);
				}
				retval = -1;
				goto cleanup;
			}
			resp = (struct inet_diag_msg *) NLMSG_DATA(nlh_resp);
			#ifdef FINDSOCKET_DEBUG
				logit("find_socket_tcp: Response: nlh_resp->nlmsg_pid=%i, nlh_resp->nlmsg_seq=%i\n", nlh_resp->nlmsg_pid, nlh_resp->nlmsg_seq);
			#endif

			if (!(resp->idiag_family == AF_INET || resp->idiag_family == AF_INET6)) {
				logit("find_socket_tcp: Unknown socket family: %i\n", resp->idiag_family);
				goto skip_it;
			}
			if (resp->idiag_inode == 0) { // Well that's of no use to anybody...
				logit("find_socket_tcp: resp->idiag_inode == 0, skipping...\n");
				goto skip_it;
			}

			lport = ntohs(resp->id.idiag_sport);
			rport = ntohs(resp->id.idiag_dport);
			if (search_ip_version == 4) {
				uint32 lip4 = -1, rip4 = -1;
				if (resp->idiag_family == AF_INET)
					lip4 = resp->id.idiag_src[0];
				else if (resp->idiag_family == AF_INET6) {
					// check for IPV4-mapped addresses on an IPv6 socket
					if (!IsIPv4inIPv6(&resp->id.idiag_src[0], &lip4)) {
						logit("find_socket_tcp: DEBUG: skipping true IPv6 socket. inode=%i\n", resp->idiag_inode);
						goto skip_it;
					}
				}
				if (resp->idiag_family == AF_INET)
					rip4 = resp->id.idiag_dst[0];
				else if (resp->idiag_family == AF_INET6) {
					// check for IPV4-mapped addresses on an IPv6 socket
					if (!IsIPv4inIPv6(&resp->id.idiag_dst[0], &rip4)) {
						logit("find_socket_tcp: DEBUG: skipping true IPv6 socket. inode=%i\n", resp->idiag_inode);
						goto skip_it;
					}
				}

#ifdef FINDSOCKET_DEBUG
				logit("  Socket Details: inode=%i, UID=%i, Type=%s, State=%i %s, LIP=%s, LPort=%i, RIP=%s, RPort=%i\n", resp->idiag_inode, resp->idiag_uid
					, resp->idiag_family == AF_INET ? "IPv4" : "IPv6", resp->idiag_state, tcp_get_state_name(resp->idiag_state)
					, lip4 == 0 ? "*" : inet_ntop(AF_INET, &lip4, lip_str, sizeof(lip_str)), lport, rip4 == 0 ? "*" : inet_ntop(AF_INET, &rip4, rip_str, sizeof(rip_str)), rport);
#endif
				if (
				    (search_lport == 0 || lport == search_lport)
				    && (search_rport == 0 || rport == search_rport)
				    // If specifying a specific local IP, and we match a socket that's listening on IPADDR_ANY, return that too. But prefer the specific IP one.
				    && (search_lip4 == 0 || lip4 == search_lip4 || (resp->idiag_state == TCP_LISTEN && lip4 == 0))
					&& (search_rip4 == 0 || rip4 == search_rip4)
				   ) {
					#ifdef FINDSOCKET_DEBUG
						logit("  Candidate match found. inode=%u\n", resp->idiag_inode);
					#endif
				   	if (prev_match_lip4 == 0 && (prev_match_family == 0 || prev_match_family == resp->idiag_family || resp->idiag_family == (in_ip_version == 4 ? AF_INET : AF_INET6))) {
						#ifdef FINDSOCKET_DEBUG
							logit("  Best match so far. inode=%u\n", resp->idiag_inode);
						#endif
						if (oINode)
							*oINode = resp->idiag_inode;
						if (oUID)
							*oUID = resp->idiag_uid;
						prev_match_lip4 = lip4;
						prev_match_family = resp->idiag_family;
					}
					num_matches++;
				}
			}
			else { // search_ip_version == 6
				void *lip6, *rip6;


				if (resp->idiag_family == AF_INET)
					goto skip_it;
				lip6 = &resp->id.idiag_src[0];
				rip6 = &resp->id.idiag_dst[0];

#ifdef FINDSOCKET_DEBUG
				logit("  Socket Details: inode=%i, UID=%i, Type=%s, State=%i %s, LIP=%s, LPort=%i, RIP=%s, RPort=%i\n", resp->idiag_inode, resp->idiag_uid, resp->idiag_family == AF_INET ? "IPv4" : "IPv6"
					, resp->idiag_state, tcp_get_state_name(resp->idiag_state), inet_ntop(AF_INET6, lip6, lip_str, sizeof(lip_str)), lport, inet_ntop(AF_INET6, rip6, rip_str, sizeof(rip_str)), rport);
#endif
				if (
				    (search_lport == 0 || lport == search_lport)
				    && (search_rport == 0 || rport == search_rport)
				    // If specifying a specific local IP, and we match a socket that's listening on IPADDR_ANY, return that too. But prefer the specific IP one.
				    && (IS_IPV6_ANYADDR(search_lip6) || memcmp(lip6, search_lip6, 16) == 0 || (resp->idiag_state == TCP_LISTEN && IS_IPV6_ANYADDR(lip6)))
					&& (IS_IPV6_ANYADDR(search_rip6) || memcmp(rip6, search_rip6, 16) == 0)
				   ) {
					#ifdef FINDSOCKET_DEBUG
						logit("  Candidate match found. inode=%u\n", resp->idiag_inode);
					#endif
				   	if (IS_IPV6_ANYADDR(prev_match_lip6)) {
						#ifdef FINDSOCKET_DEBUG
							logit("  Best match so far (IPv6). inode=%u\n", resp->idiag_inode);
						#endif
						if (oINode)
							*oINode = resp->idiag_inode;
						if (oUID)
							*oUID = resp->idiag_uid;
						memcpy(prev_match_lip6, lip6, 16);
					}
					num_matches++;
				}
			}
skip_it:
			nlh_resp = NLMSG_NEXT(nlh_resp, rv);
		}
		if (msg.msg_flags & MSG_TRUNC) {
			logit("find_socket_tcp: Message truncated, looping\n");
			continue;
		}
		if (rv) {
			logit("find_socket_tcp: !!!Remnant of size %d\n", rv);
			errno = -EBADE;
			goto cleanup;
		}
	}

	// we should never fall through to here
	errno = -EBADE;
cleanup:
	pthread_mutex_unlock(&netlink_mutex);
	#ifdef FINDSOCKET_DEBUG
		logit("find_socket_tcp: exiting with retval=%i\n", retval);
	#endif
	return retval;
}

// Returns negative for error, zero for no match found, positive for success.
// Number of candidate matches found is returned, unless an exact match is found. Output values are set to the "best" candidate match.
int find_socket_udp(uint8 in_ip_version, void* in_lip, uint16 search_lport, void* in_rip, uint16 search_rport, uint32* oINode, uid_t* oUID) {
	int retval = -2, r;
	FILE* f = NULL;
	char buf [4096];
	uint32 lip4, rip4, lip6[4], rip6[4], inode;
	uint16 lport, rport;
	uid_t uid;
   	int num_matches = 0;
	uint32 prev_match_lip4 = 0, prev_match_lip6[4] = { 0, 0, 0, 0 };
	uint8 family, prev_match_family = 0;
	uint32	search_lip4 = -1, search_rip4 = -1;
	void	*search_lip6 = NULL, *search_rip6 = NULL;
	uint8	search_ip_version = 0;
#ifdef FINDSOCKET_DEBUG
	char	lip_str[INET6_ADDRSTRLEN], rip_str[INET6_ADDRSTRLEN];
#endif

	search_ip_version = in_ip_version;
	if (in_ip_version == 6) {
		if (IsIPv4inIPv6(in_lip, &search_lip4) && IsIPv4inIPv6(in_rip, &search_rip4))
			search_ip_version = 4;
		else {
			search_lip6 = in_lip;
			search_rip6 = in_lip;
		}
	}
	else {
		search_lip4 = *((uint32*) in_lip);
		search_rip4 = *((uint32*) in_rip);
	}

//  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops             
//   32: 00000000:006F 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 11208 2 ffff88007c360340 0         
//  154: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000    70        0 11430 2 ffff88007af08000 0         
//  184: 00000000:9D07 00000000:0000 07 00000000:00000000 00:00000000 00000000    70        0 11431 2 ffff88007af08340 0         

//  sl   local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
//  691: 00000000000000000000000000000000:0302 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 11215 2 ffff88007c348400 0
//  694: 00000000000000000000000000000000:B705 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000    29        0 11578 2 ffff88007c518000 0

	for (int x=(search_ip_version == 4 ? 0 : 1); x<=1; x++) {
		family = (x == 0 ? AF_INET : AF_INET6);

		if ((f = fopen(family == AF_INET ? "/proc/net/udp" : "/proc/net/udp6", "r")) == NULL) {
			logit("find_socket_udp: failed to open %s. errno=%i (%s)\n", family == AF_INET ? "/proc/net/udp" : "/proc/net/udp6", errno, strerror(errno));
			retval = -1;
			goto cleanup;
		}
	
		if (fgets(buf, sizeof(buf), f) == NULL) {
			logit("find_socket_udp: failed to skip header line in %s. errno=%i (%s)\n", family == AF_INET ? "/proc/net/udp" : "/proc/net/udp6", errno, strerror(errno));
			errno = -ESPIPE;
			retval = -1;
			goto cleanup;
		}
		while (fgets(buf, sizeof(buf), f)) {
			if (family == AF_INET) {
				//                          LIP    RIP    State       TimerAct    UID       RefCount
				//                             LP     RP      TxQ         TimerJif   TimeOut    Pointer
				//                     Conn#                      RxQ         ReTrans    INode        Drops
				if ((r = sscanf(buf, " %*u: %x:%hx %x:%hx %*u %*x:%*x %*x:%*x %*u %u %*u %u %*u %*x %*u", &lip4, &lport, &rip4, &rport, &uid, &inode)) != 6) {
					logit("find_socket_udp: sscanf(IPv4) failed. r=%i, errno=%i (%s)\n", r, errno, strerror(errno));
					goto cleanup;
				}
#ifdef FINDSOCKET_DEBUG
//				logit("L=%s:%hu", lip == 0 ? "*" : inet_ntoa(*((struct in_addr*) &lip)), lport);
//				logit(", R=%s:%hu, INode=%u, UID=%u\n", rip == 0 ? "*" : inet_ntoa(*((struct in_addr*) &rip)), rport, inode, uid);
#endif
			}
			else {
				//                          LIP6             RIP6             State       TimerAct    UID       RefCount
				//                                       LP               RP      TxQ         TimerJif   TimeOut    Pointer
				//                     Conn#                                          RxQ         ReTrans    INode        Drops
				if ((r = sscanf(buf, " %*u: %8x%8x%8x%8x:%hx %8x%8x%8x%8x:%hx %*x %*x:%*x %*x:%*x %*u %u %*u %u %*u %*x %*u", &lip6[0], &lip6[1], &lip6[2], &lip6[3], &lport, &rip6[0], &rip6[1], &rip6[2], &rip6[3], &rport, &uid, &inode)) != 12) {
					logit("find_socket_udp: sscanf(IPv6) failed. r=%i, errno=%i (%s)\n", r, errno, strerror(errno));
					goto cleanup;
				}
#ifdef FINDSOCKET_DEBUG
//				logit("L=IPv6:%hu", lport);
//				logit(", R=IPv6:%hu, INode=%u, UID=%u\n", rport, inode, uid);
#endif

				if (search_ip_version == 4) {
					// check for IPV4-mapped addresses on an IPv6 socket
					if (!IsIPv4inIPv6(&lip6[0], &lip4))
						continue;
					if (!IsIPv4inIPv6(&rip6[0], &rip4))
						continue;
				}
			}

			#ifdef FINDSOCKET_DEBUG
				logit("  Socket Details: inode=%i, UID=%i, Type=%s, LIP=%s, LPort=%i, RIP=%s, RPort=%i\n", inode
					, uid
					, family == AF_INET ? "IPv4" : "IPv6"
					, inet_ntop(family, family == AF_INET ? &lip4 : &lip6, lip_str, sizeof(lip_str))
					, lport
					, inet_ntop(family, family == AF_INET ? &rip4 : &rip6, rip_str, sizeof(rip_str))
					, rport);
			#endif
			// Since UDP can use sendto and never has to bind() for remote IP/port, need to be flexible about matching
			// Look for an exact match, and prefer that one if we find it, but accept a match with no remote IP or port
			if (search_ip_version == 4) {
				if (lip4 == search_lip4 && lport == search_lport && rip4 == search_rip4 && rport == search_rport) {
					// exact match, must be a bound socket for this comm. Ain't gonna get better than this, stop and just return this one.
					#ifdef FINDSOCKET_DEBUG
						logit("  Exact match found, returning now. inode=%u\n", inode);
					#endif
					if (oINode)
						*oINode = inode;
					if (oUID)
						*oUID = uid;
					retval = 1;
					goto cleanup;
				}
				if (
				    (search_lport == 0 || lport == search_lport)
				    && (search_rport == 0 || rport == search_rport || rport == 0)
				    && (search_lip4 == 0 || lip4 == search_lip4 || lip4 == 0)
					&& (search_rip4 == 0 || rip4 == search_rip4 || rip4 == 0)
				   ) {
					#ifdef FINDSOCKET_DEBUG
						logit("  Candidate match found. inode=%u\n", inode);
					#endif
				   	if (prev_match_lip4 == 0 && (prev_match_family == 0 || prev_match_family == family || family == (in_ip_version == 4 ? AF_INET : AF_INET6))) {
						#ifdef FINDSOCKET_DEBUG
							logit("  Best match so far. inode=%u\n", inode);
						#endif
						if (oINode)
							*oINode = inode;
						if (oUID)
							*oUID = uid;
						prev_match_lip4 = lip4;
						prev_match_family = family;
					}
					num_matches++;
				}
			}
			else {
				if (memcmp(lip6, search_lip6, 16) == 0 && lport == search_lport && memcmp(rip6, search_rip6, 16) == 0 && rport == search_rport) {
					// exact match, must be a bound socket for this comm. Ain't gonna get better than this, stop and just return this one.
					#ifdef FINDSOCKET_DEBUG
						logit("  Exact match found, returning now. inode=%u\n", inode);
					#endif
					if (oINode)
						*oINode = inode;
					if (oUID)
						*oUID = uid;
					retval = 1;
					goto cleanup;
				}
				if (
				    (search_lport == 0 || lport == search_lport)
				    && (search_rport == 0 || rport == search_rport || rport == 0)
				    && (IS_IPV6_ANYADDR(search_lip6) || memcmp(lip6, search_lip6, 16) == 0 || IS_IPV6_ANYADDR(lip6))
					&& (IS_IPV6_ANYADDR(search_rip6) || memcmp(rip6, search_rip6, 16) == 0 || IS_IPV6_ANYADDR(rip6))
				   ) {
					#ifdef FINDSOCKET_DEBUG
						logit("  Candidate match found. inode=%u\n", inode);
					#endif
				   	if (IS_IPV6_ANYADDR(prev_match_lip6)) {
						#ifdef FINDSOCKET_DEBUG
							logit("  Best match so far. inode=%u\n", inode);
						#endif
						if (oINode)
							*oINode = inode;
						if (oUID)
							*oUID = uid;
						memcpy(prev_match_lip6, lip6, 16);
					}
					num_matches++;
				}
			}
		}

		fclose(f);
		f = NULL;
	}
	retval = num_matches;

cleanup:
	if (f)
		fclose(f);
	f = NULL;

	return retval;
}

int find_socket(uint8 ip_version, uint8 protocol, void* search_lip, uint16 search_lport, void* search_rip, uint16 search_rport, uint32 tcp_states, uint32* oINode, uid_t* oUID, pid_t* oPID, int want_pid_if_root) {
	int retval;
	pid_t pid = 0;
	uint32 inode = 0;
	uid_t uid = -1;
#ifdef FINDSOCKET_DEBUG
	char	lip_str[INET6_ADDRSTRLEN], rip_str[INET6_ADDRSTRLEN];
#endif

	#ifdef FINDSOCKET_DEBUG
		logit("find_socket: Called for ip_version=%i, protocol=%i, search_lip=%s, search_lport=%i, search_rip=%s, search_rport%i, tcp_states=%08x\n", ip_version, protocol
			,  inet_ntop(ip_version == 6 ? AF_INET6 : AF_INET, search_lip, lip_str, sizeof(lip_str)), search_lport
			,  inet_ntop(ip_version == 6 ? AF_INET6 : AF_INET, search_rip, rip_str, sizeof(rip_str)), search_rport, tcp_states);
	#endif

	switch (protocol) {
		case IPPROTO_TCP:
			if (tcp_states == TCPF_LISTEN) {
				#ifdef FINDSOCKET_DEBUG
					logit("find_socket: TCPF_LISTEN, asking cache...\n");
				#endif
				if ((pid = FindPIDFromSocketInode(CACHE_MATCHTYPE_NETINFO, CACHE_HINT_NORMAL, 0, 0, ip_version, protocol, search_lip, search_lport, &inode, &uid)) > 0) {
					#ifdef FINDSOCKET_DEBUG
						logit("find_socket: Cache hit: returning pid=%i, inode=%i, uid=%i\n", pid, inode, uid);
					#endif
					retval = 1;
					goto findsocket_exit;
				}
				#ifdef FINDSOCKET_DEBUG
					logit("find_socket: cache miss.\n");
				#endif
			}
			retval = find_socket_tcp(ip_version, search_lip, search_lport, search_rip, search_rport, tcp_states, &inode, &uid);
			break;
		case IPPROTO_UDP:
			if (tcp_states != 0) {
				logit("Error: tcp_states set to non-zero but protocol is not TCP\n");
				errno = -EINVAL;
				return -1;
			}

			retval = find_socket_udp(ip_version, search_lip, search_lport, search_rip, search_rport, &inode, &uid);
			break;
		default:
			logit("Error: protocol is not TCP or UDP\n");
			errno = -EINVAL;
			return -1;
	}
	#ifdef FINDSOCKET_DEBUG
		logit("find_socket: socket lookup complete: retval=%i, inode=%i, uid=%i\n", retval, inode, uid);
	#endif

	if (retval > 0 && (tcp_states == TCPF_LISTEN || (oPID && (uid != 0 || want_pid_if_root)))) {
		pid = FindPIDFromSocketInode(CACHE_MATCHTYPE_INODE, tcp_states == TCPF_LISTEN ? CACHE_HINT_NORMAL : CACHE_HINT_ONESHOT, inode, uid, ip_version, protocol, search_lip, search_lport, NULL, NULL);
		#ifdef FINDSOCKET_DEBUG
			logit("find_socket: PID lookup complete: pid=%i\n", pid);
		#endif
	}
	#ifdef FINDSOCKET_DEBUG
	else {
		logit("find_socket: skipping PID lookup: oUID=%s (%i), oPID=%s (%i), want_pid_if_root=%i\n", oUID ? "set" : "NULL", uid, oPID ? "set" : "NULL", pid, want_pid_if_root);
	}
	#endif
findsocket_exit:
	if (oPID)
		*oPID = pid;
	if (oINode)
		*oINode = inode;
	if (oUID)
		*oUID = uid;
	return retval;
}

uint64 GetTS() {
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	// convert to miliseconds
	return ((((uint64) t.tv_sec) * 1000) + (t.tv_nsec / 1000000));
}

int FindPIDFromSocketInode_initcache() {
	if (pthread_mutex_init(&findsock_cache_mutex, NULL) != 0) {
		logit("Error: pthread_mutex_init for findsock_cache_mutex failed. errno=%i (%s)\n", errno, strerror(errno));
		return -1;
	}
	return 0;
}
void FindPIDFromSocketInode_cleanup() {
	struct inode_cache_entry *todel;

	if (pthread_mutex_destroy(&findsock_cache_mutex) != 0)
		logit("Warning: pthread_mutex_destroy for findsock_cache_mutex failed. errno=%i (%s)\n", errno, strerror(errno));
	while (inode_cache_head) {
		todel = inode_cache_head;
		inode_cache_head = todel->next;
		free(todel);
	}
}

int FindPIDFromSocketInode_addcache(pid_t pid, int fdno) {
	char link[1024], name[1024], crap;
	ssize_t link_len;
	uint32 inode = 0;
	int rv;
	struct inode_cache_entry *newice = NULL;

	#ifdef FINDSOCKET_DEBUG
		logit("FindPIDFromSocketInode_addcache: Called for pid=%i, fd=%i\n", pid, fdno);
	#endif

	sprintf(name, "/proc/%d/fd/%i", pid, fdno);
	if ((link_len = readlink(name, link, sizeof(link) - 1)) <= 0) {
		logit("Error: FindPIDFromSocketInode_addcache: Addcache errored for pid=%i, fd=%i. readlink failed. errno=%i (%s)\n", pid, fdno, errno, strerror(errno));
		return -1;
	}
	if (link_len < sizeof(link))
		link[link_len] = 0;
	if ((rv = sscanf(link, "socket:[%u]%c", &inode, &crap)) != 1) {
		logit("Error: FindPIDFromSocketInode_addcache: sscanf failed. pid=%i, fd=%i, rv=%i, link='%s', errno=%i (%s)\n", pid, fdno, rv, link, errno, strerror(errno));
		return -1;
	}
	if (inode == 0) {
		logit("Error: FindPIDFromSocketInode_addcache: inode == 0 after sscanf. pid=%i, fd=%i, link='%s', errno=%i (%s)\n", pid, fdno, link, errno, strerror(errno));
		return -1;
	}

	if ((newice = malloc(sizeof(struct inode_cache_entry))) == NULL)
		return -1;
	memset(newice, 0, sizeof(struct inode_cache_entry));
	newice->ts = GetTS();
	newice->inode = inode;
	newice->pid = pid;
	newice->fdno = fdno;
	newice->uid = -1;
	#ifdef FINDSOCKET_DEBUG
		logit("DEBUG: FindPIDFromSocketInode_addcache: Adding new cache entry for inode=%u, pid=%i, fd=%i\n", newice->inode, newice->pid, newice->fdno);
	#endif
	pthread_mutex_lock(&findsock_cache_mutex);
	newice->next = inode_cache_head;
	inode_cache_head = newice;
	pthread_mutex_unlock(&findsock_cache_mutex);

	return 0;
}

int VerifyInodeCache(uint32 inode, pid_t pid, int fdno) {
	char target[64], link[1024], name[1024];
	ssize_t link_len;

	#ifdef FINDSOCKET_DEBUG
		logit("VerifyInodeCache: Called for inode=%u, pid=%i, fd=%i\n", inode, pid, fdno);
	#endif

	sprintf(target, "socket:[%u]", inode);
	sprintf(name, "/proc/%d/fd/%i", pid, fdno);

	if ((link_len = readlink(name, link, sizeof(link) - 1)) <= 0) {
		#ifdef FINDSOCKET_DEBUG
			logit("VerifyInodeCache: Verfication errored for inode=%u, pid=%i, fd=%i. readlink failed. errno=%i (%s)\n", inode, pid, fdno, errno, strerror(errno));
		#endif
		return -1;
	}
	if (link_len < sizeof(link))
		link[link_len] = 0;
	if (strcmp(link, target) != 0) {
		#ifdef FINDSOCKET_DEBUG
			logit("VerifyInodeCache: Verfication failed for inode=%u, pid=%i, fd=%i\n", inode, pid, fdno);
		#endif
		return 0;
	}
	#ifdef FINDSOCKET_DEBUG
		logit("VerifyInodeCache: Verfication success for inode=%u, pid=%i, fd=%i\n", inode, pid, fdno);
	#endif
	return 1;
}

#define INodeCacheRemoveEntry(cur, prev) { \
	if (prev) \
		prev->next = cur->next; \
	if (inode_cache_head == cur) \
		inode_cache_head = cur->next; \
	free(cur); \
	cur = prev; \
}

pid_t FindPIDFromSocketInode(int matchtype, uint8 cachehint, uint32 inode, uid_t uid, uint8 ip_version, uint8 protocol, void* ip, uint16 port, uint32* oINode, uid_t* oUID) {
	pid_t ret = 0;
	int haveanswer = 0;
	struct inode_cache_entry *newice = NULL;
	int fdno = 0;
#ifdef FINDSOCKET_DEBUG
	char ip_str[INET6_ADDRSTRLEN];

	logit("FindPIDFromSocketInode: Called for matchtype=%i, cachehint=%i, inode=%u, uid=%u, ip_version=%i, protocol=%i, ip=%s, port=%u\n", matchtype, cachehint, inode, uid, ip_version, protocol
		, inet_ntop(ip_version == 6 ? AF_INET6 : AF_INET, ip, ip_str, sizeof(ip_str)), port);
#endif

	pthread_mutex_lock(&findsock_cache_mutex);
	if (inode_cache_head) {
		uint64 tsnow;

		tsnow = GetTS();
		for (struct inode_cache_entry *prev = NULL, *cur = inode_cache_head; cur; prev=cur, cur = cur ? cur->next : inode_cache_head) {
			if (
				(cur->pid == 0 && (tsnow - cur->ts) > INODE_NEGCACHE_TIMEOUT)
				|| ((tsnow - cur->ts) >= INODE_CACHE_DROP_TIMEOUT)
				) {
				#ifdef FINDSOCKET_DEBUG
					logit("FindPIDFromSocketInode: Removing cache entry for expired inode=%u, pid=%i, fd=%i, ipver=%i, proto=%i, IP=%s, port=%i, ts=%llu\n", cur->inode, cur->pid, cur->fdno, cur->ip_version, cur->protocol, inet_ntop(cur->ip_version == 6 ? AF_INET6 : AF_INET, cur->ip, ip_str, sizeof(ip_str)), cur->port, cur->ts);
				#endif
				INodeCacheRemoveEntry(cur, prev)
				continue;
			}
			if (haveanswer == 0 && (
				(matchtype == CACHE_MATCHTYPE_INODE && cur->inode == inode)
				|| (matchtype == CACHE_MATCHTYPE_NETINFO && cur->ip_version == ip_version && cur->protocol == protocol && memcmp(cur->ip, ip, ip_version == 4 ? 4 : 16) == 0 && cur->port == port)
				)) {
				#ifdef FINDSOCKET_DEBUG
					if (matchtype == CACHE_MATCHTYPE_INODE)
						logit("FindPIDFromSocketInode: Found cache hit for inode=%u, pid=%i, fd=%i\n", inode, cur->pid, cur->fdno);
					else
						logit("FindPIDFromSocketInode: Found cache hit for inode=%u, pid=%i, fd=%i, ipver=%i, proto=%i, IP=%s, port=%i\n", cur->inode, cur->pid, cur->fdno, ip_version, protocol, inet_ntop(ip_version == 6 ? AF_INET6 : AF_INET, ip, ip_str, sizeof(ip_str)), port);
				#endif
				if (cur->pid != 0) { // do not verify or refresh timestamp of a negative cache entry
					if (VerifyInodeCache(cur->inode, cur->pid, cur->fdno) != 1) {
						#ifdef FINDSOCKET_DEBUG
							logit("FindPIDFromSocketInode: VerifyInodeCache failed. Removing cache entry for matched inode=%u, pid=%i, fd=%i, ipver=%i, proto=%i, IP=%s, port=%i, ts=%llu\n", cur->inode, cur->pid, cur->fdno, cur->ip_version, cur->protocol, inet_ntop(cur->ip_version == 6 ? AF_INET6 : AF_INET, cur->ip, ip_str, sizeof(ip_str)), cur->port, cur->ts);
						#endif
						INodeCacheRemoveEntry(cur, prev)
						continue;
					}
					// VerifyInodeCache no longer provides full coverage of all information in the cache, only extend timeout if it's an inode only entry
					if (cur->ip_version == 0)
						cur->ts = tsnow;
				}
				ret = cur->pid;
				if (oINode)
					*oINode = cur->inode;
				if (oUID)
					*oUID = cur->uid;
				haveanswer = 1;
				if (cachehint == CACHE_HINT_ONESHOT) { // once and done, remove from cache
					#ifdef FINDSOCKET_DEBUG
						logit("FindPIDFromSocketInode: Removing ONESHOT cache entry for inode=%u, pid=%i, fd=%i, ts=%llu due to oneshot.\n", cur->inode, cur->pid, cur->fdno, cur->ts);
					#endif
					INodeCacheRemoveEntry(cur, prev)
					continue;
				}
			}
		}
	}
	pthread_mutex_unlock(&findsock_cache_mutex);
	if (haveanswer) {
		if (ret == 0) // negative cache, we're done
			return ret;
		if (matchtype == CACHE_MATCHTYPE_NETINFO) // matched on netinfo, cache entry has full info, we're done
			return ret;
		// fall through to creating new cache entry: we had one without net info (created by precache)
	}
	else {
		if (matchtype != CACHE_MATCHTYPE_INODE || inode == 0) // was a netinfo cache lookup, we don't have an inode to look up
			return ret;

		ret = FindPIDFromSocketInode_nocache(inode, &fdno);
	}

	if (cachehint == CACHE_HINT_ONESHOT) { // skip adding to the cache
		#ifdef FINDSOCKET_DEBUG
			logit("FindPIDFromSocketInode: Not adding found entry to cache due to ONESHOT inode=%u, pid=%i, fd=%i\n", inode, ret, fdno);
		#endif
		return ret;
	}
	#ifdef FINDSOCKET_DEBUG
		logit("FindPIDFromSocketInode: Adding found entry to cache inode=%u, pid=%i, fd=%i, uid=%u, ip_version=%i, protocol=%i, ip=%s, port=%u\n", inode, ret, fdno, uid, ip_version, protocol
			, inet_ntop(ip_version == 6 ? AF_INET6 : AF_INET, ip, ip_str, sizeof(ip_str)), port);
	#endif

	if ((newice = malloc(sizeof(struct inode_cache_entry))) == NULL)
		return ret;
	memset(newice, 0, sizeof(struct inode_cache_entry));
	newice->ts = GetTS();
	newice->inode = inode;
	newice->pid = ret;
	newice->fdno = fdno;
	newice->ip_version = ip_version;
	newice->protocol = protocol;
	memcpy(newice->ip, ip, ip_version == 4 ? 4 : 16);
	newice->port = port;
	newice->uid = uid;
	pthread_mutex_lock(&findsock_cache_mutex);
	newice->next = inode_cache_head;
	inode_cache_head = newice;
	pthread_mutex_unlock(&findsock_cache_mutex);

	return ret;
}

pid_t FindPIDFromSocketInode_nocache(uint32 inode, int *pfdno) {
	DIR *d = NULL, *d2 = NULL;
	struct dirent * de;
	pid_t retval = 0;
	char target[64];
	char link[1024];
	ssize_t link_len;

	#ifdef FINDSOCKET_DEBUG
		logit("FindPIDFromSocketInode_nocache: Called for inode=%u\n", inode);
	#endif
	if (inode == 0)
		goto cleanup;

	memset(link, 0, sizeof(link));
	sprintf(target, "socket:[%u]", inode);

	if ((d = opendir("/proc/")) == NULL) {
		logit("FindPIDFromSocketInode_nocache: failed to open /proc/. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	while ((de = readdir(d)) != NULL) {
		struct dirent * de2;
		int p;
		char crap;
		char name[1024];

		if (sscanf(de->d_name, "%d%c", &p, &crap) != 1)
			continue;
		sprintf(name, "/proc/%d/fd/", p);

		if ((d2 = opendir(name)) == NULL) {
			#ifdef FINDSOCKET_DEBUG
						logit("FindPIDFromSocketInode_nocache: failed to open /proc/%d/fd/, skipping pid. errno=%i (%s)\n", p, errno, strerror(errno));
			#endif
			continue;
		}
		while ((de2 = readdir(d2)) != NULL) {
			if ((link_len = readlinkat(dirfd(d2), de2->d_name, link, sizeof(link) - 1)) <= 0)
				continue;
			if (link_len < sizeof(link))
				link[link_len] = 0;

			if (strcmp(link, target) != 0)
				continue;

			// Found it!		
			#ifdef FINDSOCKET_DEBUG
				logit("FindPIDFromSocketInode_nocache: Found PID=%u for inode=%u\n", p, inode);
			#endif
			if (pfdno) {
				if (sscanf(de2->d_name, "%i%c", pfdno, &crap) != 1)
					goto cleanup;
			}
			retval = p;
			goto cleanup;
		}
		closedir(d2);
		d2 = NULL;
	}

cleanup:
	if (d)
		closedir(d);
	d = NULL;

	if (d2)
		closedir(d2);
	d2 = NULL;

	return retval;
}
