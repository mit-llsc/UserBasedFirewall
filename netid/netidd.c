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
#define BUILD_netidd
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>

#include <linux/limits.h>
#include <arpa/inet.h>
//#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/netfilter.h>
#include <linux/inet_diag.h>

#include "netidd.h"
#include "../ident2d/tcp_states.h"

#include <sys/capability.h>
#include <sys/prctl.h>
#include <linux/securebits.h>

#define IDENT2_LOCAL 1
#define IDENT2_REMOTE 2

struct DelayRemoteQueryCache {
	struct DelayRemoteQueryCache *next;
	uint64	ts;
	uint8	ip_version;
	uint8	protocol;
	uint32	localIP[4];
	uint16	localport;
};

// globals
int gRunServer = 1;
struct packet* packethead = NULL;
int ident2_sock = -1, icmp_sock = -1, icmp6_sock = -1;
struct netid_config_struct config;
struct DelayRemoteQueryCache * drqchead = NULL;

// functions
void AddDelayRemoteQuery(uint8 ip_version, uint8 protocol, void* localIP, uint16 localport);
int CheckDelayRemoteQuery(uint8 ip_version, uint8 protocol, void* localIP, uint16 localport);
void DropPacket(struct nfq_q_handle *nfqh, struct packet **p);

// buffers for printing IPs
char src_ip_str[INET6_ADDRSTRLEN];
char dst_ip_str[INET6_ADDRSTRLEN];

void SigHandler(int sig) {
	switch (sig) {
		case SIGINT:
		case SIGTERM:
			gRunServer = 0;
			break;
	}
}

// called first time to fork. Called second time by child (with pidfile==NULL) to write out PID to the pidfile (and signal parent that we're done with startup).
void daemonize(const char* pidfile) {
	pid_t pid;
	int i;
	static int pfh = 0;
	char str[64];

	if (pidfile == NULL) {
		if (pfh) {
			sprintf(str,"%d\n",getpid());
			write(pfh, str, strlen(str));
		}
		return;
	}

	// clear the pidfile - also checks if someone else has it locked
	if ((i = open(pidfile, O_RDWR|O_CREAT, 0640)) < 0)
		exit(EXIT_FAILURE); // failed to open pidfile
	if (lockf(i, F_TLOCK, 0) < 0)
		exit(EXIT_FAILURE); // failed to lock pidfile
	ftruncate(i, 0);
	close(i);

	pid = fork();
	if (pid < 0) {
		exit(EXIT_FAILURE);
	}
	else if (pid > 0) {
		// parent process: stick around until child finishes starting up (for systemd)
		memset(str, 0, sizeof(str));
		while (waitpid(pid, NULL, WNOHANG) >= 0) {
			usleep(1000);
			if ((i = open(pidfile, O_RDONLY)) < 0)
				continue; // failed to open pidfile, maybe child is dead, but let waitpid catch that
			if (read(i, str, sizeof(str)-1) > 0) {
				if (atoi(str) == pid)
					exit(EXIT_SUCCESS);
				else
					exit(EXIT_FAILURE); // someone else won the race
			}
			close(i);
		}
		exit(EXIT_FAILURE);
	}
	// else: child process, onwards!
	
	if (setsid() < 0)
		exit(EXIT_FAILURE);

	if ((chdir("/")) < 0)
		exit(EXIT_FAILURE);

	for (i=getdtablesize(); i>=0; --i)
		close(i); // close all descriptors

	if ((i = open("/dev/null", O_RDWR)) == -1)
		exit(EXIT_FAILURE);
	if ((dup(i)) == -1) // stdout
		exit(EXIT_FAILURE);
	if ((dup(i)) == -1) // stderr
		exit(EXIT_FAILURE);

	if ((pfh = open(pidfile, O_RDWR|O_CREAT, 0640)) < 0)
		exit(EXIT_FAILURE); // failed to open pidfile
	if (lockf(pfh, F_TLOCK, 0) < 0)
		exit(EXIT_FAILURE); // failed to lock pidfile
	ftruncate(pfh, 0);

	signal(SIGHUP, SIG_IGN); // ignore HUP signal
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, &SigHandler); // catch TERM signal
	signal(SIGINT, &SigHandler); // catch SIGINT signal
}

void usage() {
	fprintf(stdout, "Usage: netidd [options]\n");
	fprintf(stdout, " -v, --version    print version and exit\n");
	fprintf(stdout, " -d, --debug      run in debug mode (no daemonize, log to screen)\n");
	fprintf(stdout, " -f <filename>    use <filename> as config file\n");
}

int main(int argc, char **argv) {
	const char* config_file = NETIDD_CONFIG;
	struct nfq_handle *nfh = NULL;
	struct nfq_q_handle *nfqh = NULL;
	int nf_sock = -1, nodaemon = 0, retval = EXIT_FAILURE, optval;
	struct timespec sig_timeout;
	sigset_t sig_set;
	struct passwd *pwd = NULL;
	cap_t caps;
	cap_value_t kept_caps[] = {
		CAP_NET_ADMIN, // for netfilter_queue
		CAP_DAC_READ_SEARCH, // traverse into /proc/##/ with grsec
		CAP_SYS_PTRACE, // open /proc/##/environ
	};

	for (int x=1; x<argc; x++) {
		if (strcmp(argv[x], "-d") == 0 || strcmp(argv[x], "--debug") == 0) {
			nodaemon = 1;
		}
		else if (strcmp(argv[x], "-v") == 0 || strcmp(argv[x], "--version") == 0) {
			fprintf(stdout, "netidd: no version scheme yet...\n");
			return 0;
		}
		else if (strcmp(argv[x], "-f") == 0) {
			x++;
			if (x >= argc) {
				usage();
				return 1;
			}
			config_file = argv[x];
		}
		else {
			fprintf(stdout, "Unknown option '%s'\n", argv[x]);
			usage();
			return 1;
		}
	}

//int load_config(const char* configfile, struct netid_config_struct* config)	
	if (load_config(config_file, &config) != 0) {
		fprintf(stderr, "load_config(%s) failed, exiting.\n", config_file);
		goto cleanup;
	}

	if (config.DropPriv_User[0]) {
		if ((pwd = getpwnam(config.DropPriv_User)) == NULL) {
			fprintf(stderr, "Error: unable to find uid for account '%s'\n", config.DropPriv_User);
			goto cleanup;
		}
	}

	umask(0077); // default permissions max: rwx-------

//	fprintf(stderr, "netidd starting up: Using queue number: %i\n", config.NetfilterQueueNum);
	if (nodaemon) {
		fprintf(stderr, "Running interactively by request...\n");
		signal(SIGTERM, &SigHandler); // catch TERM signal
		signal(SIGINT, &SigHandler); // catch SIGINT signal
		openlog("netid", LOG_NDELAY | LOG_PERROR, LOG_KERN);
	}
	else {
		daemonize(PIDFILE);
		if (openlogfile(LOGFILE) != 0)
			exit(EXIT_FAILURE);
		openlog("netid", LOG_NDELAY, LOG_KERN);
		logit("netidd starting up: Using queue number: %i\n", config.NetfilterQueueNum);
	}

	// Open netfilter queue socket
	if ((nfh = nfq_open()) == NULL) {
		logit("nfq_open() failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	logit("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(nfh, AF_INET) < 0) {
		logit("nfq_unbind_pf() failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	logit("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(nfh, AF_INET) < 0) {
		logit("nfq_bind_pf() failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	
	logit("binding this socket to queue '0'\n");
	if ((nfqh = nfq_create_queue(nfh, config.NetfilterQueueNum, &nfqueue_cb, NULL)) == NULL) {
		logit("nfq_create_queue() failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	logit("setting copy_packet mode\n");
	if (nfq_set_mode(nfqh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		logit("nfq_set_mode() failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	
	logit("setting uid/gid retrival and fragmentation mode\n");
	if (nfq_set_queue_flags(nfqh, NFQA_CFG_F_GSO | NFQA_CFG_F_UID_GID, NFQA_CFG_F_GSO | NFQA_CFG_F_UID_GID) < 0) {
		logit("nfq_set_queue_flags() failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	
	if ((nf_sock = nfq_fd(nfh)) < 0) {
		logit("nfq_fd() failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	// Open ICMP socket
	if ((icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
		logit("socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	optval = 1;
	if (setsockopt(icmp_sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) ){
		logit("setsockopt(icmp_sock, IP_HDRINCL) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	// Open ICMPv6 socket
	if ((icmp6_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) == -1) {
		logit("socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPv6) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
#ifdef LINUX45 // need Linux 4.5+ for IPV6_HDRINCL
	optval = 1;
	if (setsockopt(icmp6_sock, IPPROTO_IPV6, IPV6_HDRINCL, &optval, sizeof(optval)) ){
		logit("setsockopt(icmp6_sock, IP6_HDRINCL) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
#endif

	// Turn on keep caps and turn off fixups
	if (prctl(PR_SET_KEEPCAPS, 1) != 0) {
		logit("prctl(PR_SET_KEEPCAPS, 1) failed. errno=%i (%s)\n", errno, strerror(errno));
//	if (prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_NOROOT | SECBIT_NOROOT_LOCKED) != 0) {
//		logit("prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_NOROOT | SECBIT_NOROOT_LOCKED) failed. errno=%i (%s)\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	if (pwd) {
		// switch to our unprivileged user
		// do this before dropping caps: once we drop CAP_SETUID/GID we can't switch users anymore!
		if (initgroups(pwd->pw_name, pwd->pw_gid) != 0) {
			logit("initgroups() failed. errno=%i (%s)\n", errno, strerror(errno));
			goto cleanup;
		}
		if (setgid(pwd->pw_gid) != 0) {
			logit("setgid() failed. errno=%i (%s)\n", errno, strerror(errno));
			goto cleanup;
		}
		if (setuid(pwd->pw_uid) != 0) {
			logit("setuid() failed. errno=%i (%s)\n", errno, strerror(errno));
			goto cleanup;
		}
	}
	
	// Drop caps
	if ((caps = cap_init()) == NULL) {
		logit("cap_init() failed. errno=%i (%s)\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (cap_clear(caps) != 0) {
		logit("cap_clear() failed. errno=%i (%s)\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (cap_set_flag(caps, CAP_EFFECTIVE, sizeof(kept_caps)/sizeof(cap_value_t), kept_caps, CAP_SET) != 0) {
		logit("cap_set_flag(CAP_EFFECTIVE) failed. errno=%i (%s)\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (cap_set_flag(caps, CAP_PERMITTED, sizeof(kept_caps)/sizeof(cap_value_t), kept_caps, CAP_SET) != 0) {
		logit("cap_set_flag(CAP_PERMITTED) failed. errno=%i (%s)\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (cap_set_proc(caps) != 0) {
		logit("cap_set_proc()[1] failed. errno=%i (%s)\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	cap_free(caps);

	// Block the SIGIO signal so we can catch pending SIGIOs later with sigtimedwait
	if (sigemptyset(&sig_set) != 0) {
		logit("sigemptyset() failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	if (sigaddset(&sig_set, SIGIO) != 0) {
		logit("sigaddset(SIGIO) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	if (sigprocmask(SIG_BLOCK, &sig_set, NULL) != 0) {
		logit("sigprocmask(SIG_BLOCK, SIGIO) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	// Connect after dropping privs, will implicitly test the auto-reconnect that could happen in the main loop
	if (ConnectIdent2Sock() != 1) {
		logit("Failed to connect to ident2d socket at bootup. Exiting.\n");
		goto cleanup;
	}

	sig_timeout.tv_sec = 0;
	sig_timeout.tv_nsec = 250000000; // 250ms

	// set nonblocking and SIGIO on our netfilter socket
	if (fcntl(nf_sock, F_SETOWN, getpid()) < 0) {
		logit("fcntl(nf_sock, F_SETOWN) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	if (fcntl(nf_sock, F_SETFL, O_NONBLOCK | O_ASYNC) < 0) {
		logit("fcntl(nf_sock, O_NONBLOCK | O_ASYNC) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	daemonize(NULL);

	while (gRunServer) {
		int rv;
		uint8 buffer[65536];

		while ((rv = recv(nf_sock, buffer, sizeof(buffer), 0)) >= 0) {
			int rv2;
#ifdef DEBUG_LOG
			logit("---------------------------\n");
			logit("nf pkt received: rv=%i\n", rv);
#endif
			if ((rv2 = nfq_handle_packet(nfh, (char*) buffer, rv)) != 0) {
				logit("nfq_handle_packet() failed. rv2=%i, rv=%i\n", rv2, rv);
				goto cleanup;
			}
		}
		if (!(errno == EWOULDBLOCK || errno == EAGAIN || errno == ECONNABORTED)) {
			logit("recv(nf_sock) failed. errno=%i (%s)\n", errno, strerror(errno));
			goto cleanup;
		}

		if (ident2_sock >= 0) {
			struct msghdr msg;
			struct iovec iov[2];
			uint8 opcode;

			iov[0].iov_base = &opcode;
			iov[0].iov_len = sizeof(opcode);
			iov[1].iov_base = buffer;
			iov[1].iov_len = sizeof(buffer);

			memset(&msg, 0, sizeof(msg));
			msg.msg_iov = iov;
			msg.msg_iovlen = 2;

			while (1) {
				iov[1].iov_len = sizeof(buffer);
				rv = recvmsg(ident2_sock, &msg, 0);
				if (rv <= 0) {
					if (rv == 0 || errno == ECONNRESET) {
						logit("Lost connection to ident2d\n");
						close(ident2_sock);
						ident2_sock = -1;
						drop_all_packets(nfqh);
						break;
					}
					if (errno == EWOULDBLOCK || errno == EAGAIN)
						break;
					logit("recvmsg(ident2_sock) errored. errno=%i (%s)\n", errno, strerror(errno));
					goto cleanup;
				}
				else if ( rv < (sizeof(struct query_sock_response) + sizeof(opcode)) ) {
					logit("Warning: recvmsg(ident2_sock) returned message too short to be useful. Dropping ident2d connection. rv=%i\n", rv);
					close(ident2_sock);
					ident2_sock = -1;
					drop_all_packets(nfqh);
				}
				else if (opcode != OP_QueryLocalConnectionResponse && opcode != OP_QueryRemoteConnectionResponse) {
					logit("Warning: recvmsg(ident2_sock) returned unexpected opcode. Dropping ident2d connection. opcode=%i\n", opcode);
					close(ident2_sock);
					ident2_sock = -1;
					drop_all_packets(nfqh);
				}
				else {
					// got actionable message
					struct query_sock_response *qsr = (struct query_sock_response *) &buffer[0];
					struct packet * p = NULL;

#ifdef DEBUG_LOG
					logit("---------------------------\n");
					logit("Got ident2d response: %s\n", opcode == OP_QueryLocalConnectionResponse ? "OP_QueryLocalConnectionResponse" : "OP_QueryRemoteConnectionResponse");
					logit("queryid: 0x%016llx\n", qsr->queryid);
					logit("flags: %i\n", qsr->flags);
					logit("pid: %i\n", qsr->pid);
					logit("uid: %i\n", qsr->uid);
					logit("gid: %i\n", qsr->gid);
					logit("nsgids: %i\n", qsr->nsgids);
					for (int x=0; x<qsr->nsgids; x++)
						logit("sgids[%i]: %i\n", x, qsr->sgids[x]);
#endif

					if ((p = FindPacketByQueryID(qsr->queryid)) == NULL) {
#ifdef DEBUG_LOG
						logit("Notice: Received ident2d response with queryID not in packet list, ignoring. queryID=0x%016llx, packetID=%i\n", qsr->queryid, (uint32) (qsr->queryid & 0xFFFFFFFF));
#endif
						continue;
					}
					if (opcode == OP_QueryLocalConnectionResponse) {
						if (qsr->flags & QS_Flag_HaveAnswer) {
							p->have_local_answer = 1;
							p->local_uid = qsr->uid;
							if (qsr->flags & QS_Flag_PGIDInfo) {
								p->have_local_answer = 2;
								p->local_gid = qsr->gid;
							}
							if (qsr->flags & QS_Flag_ProcessInfo) {
								p->have_local_answer = 3;
								p->local_pid = qsr->pid;
								p->local_gid = qsr->gid;
							}
						}
						else {
#ifdef DEBUG_LOG
							logit("Notice: Received ident2d local response without an answer. queryID=0x%016llx, packetID=%i, qsr->flags=%i\n", qsr->queryid, qsr->queryid & 0xFFFFFFFF, qsr->flags);
#endif
							p->have_local_answer = -1;
						}
					}
					else if (opcode == OP_QueryRemoteConnectionResponse) {
						if (qsr->flags & QS_Flag_HaveAnswer) {
							p->have_remote_answer = 1;
							p->remote_uid = qsr->uid;
							if (qsr->flags & QS_Flag_PGIDInfo) {
								p->have_remote_answer = 2;
								p->remote_gid = qsr->gid;
							}
							if ((qsr->flags & QS_Flag_ProcessInfo) && (qsr->flags & QS_Flag_SupGroups)) {
								if (qsr->nsgids > NGROUPS_MAX) {
#ifdef DEBUG_LOG
									logit("Notice: Received ident2d remote response with more sgids claimed than supported by operating system. queryID=0x%016llx, packetID=%i, nsgids=%i\n", qsr->queryid, qsr->queryid & 0xFFFFFFFF, qsr->nsgids);
#endif
								}
								else if ( ( rv - (sizeof(struct query_sock_response) + sizeof(opcode)) ) != (qsr->nsgids * sizeof(gid_t)) ) {
#ifdef DEBUG_LOG
									logit("Notice: Received ident2d remote response with more sgids claimed than the packet is big. queryID=0x%016llx, packetID=%i, rv=%i, nsgids=%i\n", qsr->queryid, qsr->queryid & 0xFFFFFFFF, rv, qsr->nsgids);
#endif
								}
								else {
									p->have_remote_answer = 3;
									p->remote_gid = qsr->gid;
									p->remote_nsgids = qsr->nsgids;
									if ((p->remote_sgids = malloc(qsr->nsgids * sizeof(gid_t))) == NULL) {
										logit("Error: malloc failed for p->remote_sgids. queryID=0x%016llx, packetID=%i, nsgids=%i\n", qsr->queryid, qsr->queryid & 0xFFFFFFFF, qsr->nsgids);
										goto cleanup;
									}
									memcpy(p->remote_sgids, qsr->sgids, qsr->nsgids * sizeof(gid_t));
								}
							}
						}
						else {
#ifdef DEBUG_LOG
							logit("Notice: Received ident2d remote response without an answer. queryID=0x%016llx, packetID=%i, qsr->flags=%i\n", qsr->queryid, qsr->queryid & 0xFFFFFFFF, qsr->flags);
#endif
							p->have_remote_answer = -1;
						}
					}
					MakeDecisionOnPacket(nfqh, p, opcode); // May or may not make the decision, depending on if it has enough info
					p = NULL; // MakeDecisionOnPacket will free the packet if it actually decides something
				}
			}
		}
		if (ident2_sock == -1) {
			if (ConnectIdent2Sock(&ident2_sock) == -1) {
//				logit("Error: ConnectIdent2Sock() failed. errno=%i (%s)\n", errno, strerror(errno));
				goto cleanup;
			}
		}

		if (packethead) {
			uint64 tsnow = GetTS();
			for (struct packet *p = packethead; p; p = p ? p->next : packethead) {
				if ((tsnow - p->ts) >= config.NoAnswer_SilentDrop_TimeoutMS) {
#ifdef DEBUG_LOG
					logit("DEBUG: Silently dropping packet %i: timeout\n", p->id);
#endif
					if (config.LogDeniesToSyslog)
						syslog(LOG_NOTICE, "dropping packet: timeout: ID=%i IPver=%hhu Proto=%s SrcIP=%s DstIP=%s SrcPort=%hu DstPort=%hu LA=%hhi RA=%hhi LUID=%u RUID=%u"
							, p->id
							, p->ip_version
							, p->protocol == IPPROTO_TCP ? "TCP" : p->protocol == IPPROTO_UDP ? "UDP" : "unknown"
							, inet_ntop(p->ip_version == 4 ? AF_INET : AF_INET6, p->saddr, src_ip_str, sizeof(src_ip_str))
							, inet_ntop(p->ip_version == 4 ? AF_INET : AF_INET6, p->daddr, dst_ip_str, sizeof(dst_ip_str))
							, p->sport
							, p->dport
							, p->have_local_answer
							, p->have_remote_answer
							, p->have_local_answer > 0 ? p->local_uid : -1
							, p->have_remote_answer > 0 ? p->remote_uid : -1
							);
					DropPacket(nfqh, &p);
				}
			}
		}

		// No packets available. steady, hold, Hold, HOLD!
		rv = sigtimedwait(&sig_set, NULL, &sig_timeout); // sleep until we get a SIGIO notiication, or 250ms, or interrupted by some other signal handler, whichever comes first
#ifdef DEBUG_LOG
		if (rv != -1)
			logit("DEBUG: sigtimedwait rv=%i, errno=%i (%s)\n", rv, errno, strerror(errno));
#endif
	}
	logit("reached end of main, exiting.\n");
	retval = 0;

cleanup:
	if (icmp6_sock != -1)
		close(icmp6_sock);
	icmp6_sock = -1;

	if (icmp_sock != -1)
		close(icmp_sock);
	icmp_sock = -1;

	if (ident2_sock != -1)
		close(ident2_sock);
	ident2_sock = -1;

	if (nf_sock != -1)
		close(nf_sock);
	nf_sock = -1;

	if (nfqh) {
		drop_all_packets(nfqh);
		nfq_destroy_queue(nfqh);
	}
	nfqh = NULL;

	if (nfh)
		nfq_close(nfh);
	nfh = NULL;

	closelogfile();
	closelog(); // syslog

	return retval;
}

// 1=Success, 0=Failed, -1=Error
int ConnectIdent2Sock() {
	// try connection to ident2d
	struct sockaddr_un addr;

	if ((ident2_sock = socket(PF_UNIX, SOCK_SEQPACKET, 0)) < 0) {
		logit("Error: socket() for ident2_sock failed. errno=%i (%s)\n", errno, strerror(errno));
		ident2_sock = -1;
		return 0;
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, IDENT2_SOCKNAME, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path)-1] = '\0';

	if (connect( ident2_sock, (struct sockaddr *) &addr, sizeof(addr) ) != 0) {
//		logit("Error: connect(ident2_sock) failed. errno=%i (%s)\n", errno, strerror(errno));
		close(ident2_sock);
		ident2_sock = -1;
		return 0;
	}

	// set nonblocking and SIGIO on our ident2d socket
	if (fcntl(ident2_sock, F_SETOWN, getpid()) < 0) {
		logit("fcntl(ident2_sock, F_SETOWN) failed. errno=%i (%s)\n", errno, strerror(errno));
		return -1;
	}
	if (fcntl(ident2_sock, F_SETFL, O_NONBLOCK | O_ASYNC) < 0) {
		logit("fcntl(ident2_sock, O_NONBLOCK | O_ASYNC) failed. errno=%i (%s)\n", errno, strerror(errno));
		return -1;
	}
	logit("Successfully connected to ident2d.\n");
	return 1;
}

struct packet * FindPacketByQueryID(uint64 queryID) {
	uint32 HighQueryID = queryID >> 32;
	int id = queryID & 0xFFFFFFFF;

	for (struct packet *p = packethead; p; p = p ? p->next : packethead) {
		if (p->highQueryID == HighQueryID && p->id == id) {
			return p;
		}
	}
	return NULL;
}

void AcceptPacket(struct nfq_q_handle *nfqh, struct packet *p) {
	if (nfq_set_verdict(nfqh, p->id, NF_ACCEPT, 0, NULL) < 0) {
		logit("AcceptPacket: Warning: nfq_set_verdict failed. p->id=%i, errno=%i (%s)\n", p->id, errno, strerror(errno));
	}
	removepacket(&p);
}

void DropPacket(struct nfq_q_handle *nfqh, struct packet **p) {
	if (nfq_set_verdict(nfqh, (*p)->id, NF_DROP, 0, NULL) < 0) {
		logit("DropPacket: Warning: nfq_set_verdict failed. rv=%i, p->id=%i, errno=%i (%s)\n", (*p)->id, errno, strerror(errno));
	}
	removepacket(p);
}

void RejectPacket(struct nfq_q_handle *nfqh, struct packet *p) {
	if (send_icmp_admin_prohibited(p->ip_version, p->packet_data, p->packet_data_size) != 0) {
		logit("RejectPacket: Warning: send_icmp_admin_prohibited failed. p->id=%i, errno=%i (%s)\n", p->id, errno, strerror(errno));
	}
	DropPacket(nfqh, &p);
}

void RefusePacket(struct nfq_q_handle *nfqh, struct packet *p) {
	if (send_icmp_port_unreachable(p->ip_version, p->packet_data, p->packet_data_size) != 0) {
		logit("RefusePacket: Warning: send_icmp_port_unreachable failed. p->id=%i, errno=%i (%s)\n", p->id, errno, strerror(errno));
	}
	DropPacket(nfqh, &p);
}

int CheckUIDRanges(struct netid_config_uid_range *ranges, uid_t uid) {
	#ifdef DEBUG_LOG
		logit("CheckUIDRanges: DEBUG: uid=%i\n", uid);
	#endif
	for (uint32 x=0; x<NETID_CONFIG_MAX_UIDS; x++) {
		#ifdef DEBUG_LOG
			logit("CheckUIDRanges: DEBUG: x=%i, min=%i, max=%i\n", x, ranges[x].min, ranges[x].max);
		#endif
		if (ranges[x].min > ranges[x].max)
			break;
		if (uid >= ranges[x].min && uid <= ranges[x].max)
			return 1;
	}
	#ifdef DEBUG_LOG
		logit("CheckUIDRanges: DEBUG: no match, returning 0\n");
	#endif
	return 0;
}

// returns 1 if decision made, zero if still pending
int MakeDecisionOnPacket(struct nfq_q_handle *nfqh, struct packet *p, uint8 opcode) {
	gid_t local_gid_to_check = p->local_gid;
	// have_*_answer: 0 = waiting, 1 >= answered, -1 = reply without answer, -2 = delayed asking

	// if we have both answers, check the uids - no need to spend time with the environment var if we can stop here...
	if (p->have_local_answer >= 1 && p->have_remote_answer >= 1) {
		if (p->local_uid == p->remote_uid) {
			#ifdef DEBUG_LOG
				logit("MakeDecisionOnPacket: Accepting Packet: p->local_uid (%i) == p->remote_uid (%i)\n", p->local_uid, p->remote_uid);
			#endif
			AcceptPacket(nfqh, p); p = NULL;
			return 1;
		}
	}

	// accept if remote process is exempt for connecting
	if (opcode == OP_QueryRemoteConnectionResponse && p->have_remote_answer >= 1 && CheckUIDRanges(config.ExemptConnectUIDs, p->remote_uid)) {
		#ifdef DEBUG_LOG
			logit("MakeDecisionOnPacket: Accepting Packet: p->remote_uid in config.ExemptConnectUIDs\n");
		#endif
		AcceptPacket(nfqh, p); p = NULL;
		return 1;
	}

	if (p->have_local_answer >= 1) {
		// accept if local process is exempt for listening
		if (opcode == OP_QueryLocalConnectionResponse && CheckUIDRanges(config.ExemptListenUIDs, p->local_uid)) {
			#ifdef DEBUG_LOG
				logit("MakeDecisionOnPacket: Accepting Packet: p->local_uid in config.ExemptListenUIDs\n");
			#endif
			AddDelayRemoteQuery(p->ip_version, p->protocol, p->daddr, p->dport);
			AcceptPacket(nfqh, p); p = NULL;
			return 1;
		}
	}

	// if we have both answers, check the gids
	if (p->have_local_answer >= 1 && p->have_remote_answer >= 1) {
		// If GetConnectorGroupsFromUserDB we look up the groups info from the user database
		if (config.GetConnectorGroupsFromUserDB && p->have_remote_answer == 1) {
			struct passwd *ruserinfo = NULL;
			if ((ruserinfo = getpwuid(p->remote_uid)) != NULL) {
				p->remote_gid = ruserinfo->pw_gid;
				p->remote_nsgids = NGROUPS_MAX;
				if ((p->remote_sgids = malloc(p->remote_nsgids * sizeof(gid_t))) != NULL) {
					if (getgrouplist(ruserinfo->pw_name, ruserinfo->pw_gid, p->remote_sgids, &p->remote_nsgids) >= 0) {
						p->have_remote_answer = 2;
					}
					else {
						logit("MakeDecisionOnPacket: getgrouplist failed.\n");
					}
				}
				else {
					logit("MakeDecisionOnPacket: malloc failed for p->remote_sgids.\n");
				}
			}
			else {
				logit("MakeDecisionOnPacket: Failed to query user %i.\n", p->remote_uid);
			}
		}
		if (p->have_remote_answer >= 2) {
			if (local_gid_to_check == p->remote_gid) {
				#ifdef DEBUG_LOG
					logit("MakeDecisionOnPacket: Accepting Packet: local_gid_to_check (%i) == p->remote_gid (%i)\n", local_gid_to_check, p->remote_gid);
				#endif
				AcceptPacket(nfqh, p); p = NULL;
				return 1;
			}
		}
		if (p->have_remote_answer >= 3) {
			if (p->remote_nsgids && p->remote_sgids) {
				for (uint32 x=0; x<p->remote_nsgids; x++) {
					if (local_gid_to_check == p->remote_sgids[x]) {
						#ifdef DEBUG_LOG
							logit("MakeDecisionOnPacket: Accepting Packet: local_gid_to_check (%i) == p->remote_sgids[%i] (%i)\n", local_gid_to_check, x, p->remote_sgids[x]);
						#endif
						AcceptPacket(nfqh, p); p = NULL;
						return 1;
					}
				}
			}
		}
	
		#ifdef DEBUG_LOG
			logit("MakeDecisionOnPacket: Rejecting Packet: no matching gids or sgids: HID=%08x LID=%08x IPver=%hhu Proto=%s SrcIP=%s DstIP=%s SrcPort=%hu DstPort=%hu LUID=%u RUID=%u LGID=%u"
                                , p->highQueryID
                                , p->id
                                , p->ip_version
                                , p->protocol == IPPROTO_TCP ? "TCP" : p->protocol == IPPROTO_UDP ? "UDP" : "unknown"
                                , inet_ntop(p->ip_version == 4 ? AF_INET : AF_INET6, p->saddr, src_ip_str, sizeof(src_ip_str))
                                , inet_ntop(p->ip_version == 4 ? AF_INET : AF_INET6, p->daddr, dst_ip_str, sizeof(dst_ip_str))
                                , p->sport
                                , p->dport
                                , p->local_uid
                                , p->remote_uid
                                , p->local_gid
                                );

		#endif
		if (config.LogDeniesToSyslog)
			syslog(LOG_NOTICE, "rejecting packet: no matching uid, gids or sgids: HID=%08x LID=%08x IPver=%hhu Proto=%s SrcIP=%s DstIP=%s SrcPort=%hu DstPort=%hu LUID=%u RUID=%u LGID=%u"
				, p->highQueryID
				, p->id
				, p->ip_version
				, p->protocol == IPPROTO_TCP ? "TCP" : p->protocol == IPPROTO_UDP ? "UDP" : "unknown"
				, inet_ntop(p->ip_version == 4 ? AF_INET : AF_INET6, p->saddr, src_ip_str, sizeof(src_ip_str))
				, inet_ntop(p->ip_version == 4 ? AF_INET : AF_INET6, p->daddr, dst_ip_str, sizeof(dst_ip_str))
				, p->sport
				, p->dport
				, p->local_uid
				, p->remote_uid
				, p->local_gid
				);
		RejectPacket(nfqh, p); p = NULL;
		return 1;
	}

	if (opcode == OP_QueryLocalConnectionResponse && p->have_remote_answer == -2) {
		// we delayed asking the remote side because we had a cache hit... but that didn't work out. So ask them now.
		#ifdef DEBUG_LOG
			logit("MakeDecisionOnPacket: Sending delayed Ident2 remote query.\n");
		#endif
		// kernel inet_diag.c has two lookups: one for (TCPF_LISTEN | TCPF_SYN_RECV) and a seperate one for all other flags
		if (AskIdent2(IDENT2_REMOTE, GetPacketQueryID(p), p->ip_version, p->protocol, p->saddr, p->sport, p->daddr, p->dport, NETIDD_TCPFLAGS_REMOTE) != 0) {
			logit("MakeDecisionOnPacket: AskIdent2() failed, silent dropping packet. errno=%i (%s)\n", errno, strerror(errno));
			DropPacket(nfqh, &p); p = NULL;
			return 1;
		}
		p->have_remote_answer = 0;
	}

	// reject if both sides have replied with all the info we're gonna get, and none of the above hit
	if (p->have_local_answer != 0 && p->have_remote_answer != 0) {
		#ifdef DEBUG_LOG
			logit("MakeDecisionOnPacket: Rejecting Packet: response without an answer from one side or the other (HID=%08x LID=%08x p->have_local_answer=%i, p->have_remote_answer=%i).\n", (unsigned long int) p->highQueryID, (unsigned long int) p->id, p->have_local_answer, p->have_remote_answer);
		#endif
		if (config.LogDeniesToSyslog)
			syslog(LOG_NOTICE, "%s packet: response without information: HID=%08x LID=%08x IPver=%hhu Proto=%s SrcIP=%s DstIP=%s SrcPort=%hu DstPort=%hu LA=%hhi RA=%hhi LUID=%u RUID=%u"
				, (p->have_local_answer < 0 ? "refusing" : "rejecting")
				, p->highQueryID
				, p->id
				, p->ip_version
				, p->protocol == IPPROTO_TCP ? "TCP" : p->protocol == IPPROTO_UDP ? "UDP" : "unknown"
				, inet_ntop(p->ip_version == 4 ? AF_INET : AF_INET6, p->saddr, src_ip_str, sizeof(src_ip_str))
				, inet_ntop(p->ip_version == 4 ? AF_INET : AF_INET6, p->daddr, dst_ip_str, sizeof(dst_ip_str))
				, p->sport
				, p->dport
				, p->have_local_answer
				, p->have_remote_answer
				, p->have_local_answer > 0 ? p->local_uid : -1
				, p->have_remote_answer > 0 ? p->remote_uid : -1
				);
		if (p->have_local_answer < 0) { // port not open?
			RefusePacket(nfqh, p); p = NULL;
		}
		else {
			RejectPacket(nfqh, p); p = NULL;
		}
		return 1;
	}

	// else wait for more info
	#ifdef DEBUG_LOG
		logit("MakeDecisionOnPacket: Waiting for more info.\n");
	#endif
	return 0;
}

void drop_all_packets(struct nfq_q_handle *nfqh) {
	for (struct packet *p = packethead; p; p = p ? p->next : packethead)
		DropPacket(nfqh, &p);
}

// Remove the packet and set the pointer to the previous packet (assuming that a loop is about to set it to next)
void removepacket(struct packet **p) {
	struct packet *p2 = (*p)->prev;

	if ((*p)->next)
		(*p)->next->prev = (*p)->prev;
	if ((*p)->prev)
		(*p)->prev->next = (*p)->next;
	if (packethead == *p)
		packethead = (*p)->next;
	if ((*p)->packet_data)
		free((*p)->packet_data);
	if ((*p)->remote_sgids)
		free((*p)->remote_sgids);
	free(*p);

	*p = p2;
}

uint64 GetTS() {
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	// convert to miliseconds
	return ((((uint64) t.tv_sec) * 1000) + (t.tv_nsec / 1000000));
}

struct packet * newpacket(int np_id, uint8* new_packetdata, uint32 new_packetdatasize) {
	static uint32 NextHighQueryID = 0;
	struct packet *np;

	if ((np = (struct packet *) malloc(sizeof(struct packet))) == NULL) {
		errno = -ENOMEM;
		return NULL;
	}
	memset(np, 0, sizeof(struct packet));
	np->ts = GetTS();
	np->id = np_id;
	np->highQueryID = ++NextHighQueryID;
	// make a copy of the packet data, this buffer will go away when the netfilter callback ends and we need it for the ICMP unreachable reply
	if ((np->packet_data = malloc(new_packetdatasize)) == NULL) {
		free(np);
		errno = -ENOMEM;
		return NULL;
	}
	memcpy(np->packet_data, new_packetdata, new_packetdatasize);
	np->packet_data_size = new_packetdatasize;
	if (packethead)
		packethead->prev = np;
	np->next = packethead;
	packethead = np;

	return np;
}

uint64 GetPacketQueryID(struct packet *p) {
	return ( (((uint64) p->highQueryID) << 32) | ((uint32) p->id) );
}

int AskIdent2(uint8 LocalOrRemote, uint64 queryID, uint8 ip_version, uint8 protocol, void* lIP, uint16 lPort, void* rIP, uint16 rPort, uint32 tcp_states) {
	struct msghdr msg;
	struct iovec iov[2];
	char opcode;
	struct query_sock qs;
#ifdef DEBUG_LOG
	char ip_str[INET6_ADDRSTRLEN];
#endif

	if (ident2_sock == -1) {
		errno = -ENOTCONN;
		return -1;
	}

	if (LocalOrRemote == IDENT2_LOCAL)
		opcode = OP_QueryLocalConnection;
	else if (LocalOrRemote == IDENT2_REMOTE)
		opcode = OP_QueryRemoteConnection;
	else {
		errno = -EINVAL;
		return -1;
	}

	memset(&qs, 0, sizeof(qs));
	qs.queryid = queryID;
	qs.flags = 0;
	qs.flags = ((LocalOrRemote == IDENT2_REMOTE && config.GetConnectorGroupsFromUserDB) ? 0 : (QS_Flag_ProcessInfo | QS_Flag_SupGroups));
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
	logit("Sending ident2d question:\n");
	logit("queryID: 0x%llx\n", queryID);
	logit("opcode: %s\n", opcode == OP_QueryLocalConnection ? "OP_QueryLocalConnection" : "OP_QueryRemoteConnection");
	logit("queryid: 0x%016llx\n", qs.queryid);
	logit("flags: %i\n", qs.flags);
	logit("version: %i\n", qs.ip_version);
	logit("protocol: %i\n", qs.protocol);
	logit("tcpstates: %i (0x%08x)\n", qs.tcpstates, qs.tcpstates);
	logit("local_ip: %s\n", inet_ntop(ip_version == 4 ? AF_INET : AF_INET6, qs.local_ip, ip_str, sizeof(ip_str)));
	logit("local_port: %i\n", qs.local_port);
	logit("remote_ip: %s\n", inet_ntop(ip_version == 4 ? AF_INET : AF_INET6, qs.remote_ip, ip_str, sizeof(ip_str)));
	logit("remote_port: %i\n", qs.remote_port);
	logit("---------------------------\n");
#endif

	iov[0].iov_base = &opcode;
	iov[0].iov_len = 1;
	iov[1].iov_base = &qs;
	iov[1].iov_len = sizeof(qs);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	if (sendmsg(ident2_sock, &msg, 0) == -1) {
		if (errno == 11) {
			#ifdef DEBUG_LOG
				logit("AskIdent2: Notice: sendmsg(ident2_sock) failed with Resource Temporarily Unavailable. Buffers are full... drop this packet but carry on. errno=%i (%s)\n", errno, strerror(errno));
			#endif
		}
		else {
			logit("AskIdent2: Error: sendmsg(ident2_sock) failed, closing socket. errno=%i (%s)\n", errno, strerror(errno));
			close(ident2_sock);
			ident2_sock = -1;
		}
		return -1;
	}
	//fprintf(stdout, "Query*Connection request sent!\n");
	return 0;
}

// Send question to ident2d & queue packet into our list to monitor for timeout.
// Note: this is a long chain of callbacks, our return value shows up as the return of nfq_handle_packet in our main()
int nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data) {
	struct nfqnl_msg_packet_hdr *ph;
	int id = 0, size = 0;
	uint8* full_packet = NULL;
	struct iphdr * iph = NULL;
	struct ipv6hdr * iph6 = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	uint8 ip_version = 0;
	uint8 ip_protocol = 0;
	void * saddr = NULL;
	void * daddr = NULL;
	uint32 l4_header_start = -1;
	
	if ((ph = nfq_get_msg_packet_hdr(nfad)) == NULL) {
		logit("nfqueue_cb: Fatal Error: nfq_get_msg_packet_hdr() returned NULL. errno=%i (%s)\n", errno, strerror(errno));
		gRunServer = 0; // crash and burn
		return -1;
	}

	id = ntohl(ph->packet_id);

	// Retrieve packet payload.
	if ((size = nfq_get_payload(nfad, (unsigned char**) &full_packet)) < 0 || full_packet == NULL) {
		logit("nfqueue_cb: Fatal Error: nfq_get_payload() errored. Silently dropping packet. size=%i. errno=%i (%s)\n", size, errno, strerror(errno));
		if (nfq_set_verdict(qh, id, NF_DROP, 0, NULL) < 0) {
			logit("nfqueue_cb: Warning: nfq_set_verdict failed. id=%i, errno=%i (%s)\n", id, errno, strerror(errno));
		}
		gRunServer = 0; // crash and burn
		return -1;
	}

	if (size < 20) {
		logit("nfqueue_cb: Error: packet size is smaller than minimum IP header. Silently dropping packet. size=%i\n", size);
		if (nfq_set_verdict(qh, id, NF_DROP, 0, NULL) < 0) {
			logit("nfqueue_cb: Warning: nfq_set_verdict failed. id=%i, errno=%i (%s)\n", id, errno, strerror(errno));
		}
		return 0;
	}
	iph = (struct iphdr *) full_packet;
	ip_version = iph->version;
	if (ip_version == 4) {
		ip_protocol = iph->protocol;
		if (size < (iph->ihl*4)) {
			logit("nfqueue_cb: Error: packet size is smaller than claimed IP header length. Silently dropping packet. (iph->ihl=%i) * 4. size=%i\n", iph->ihl, size);
			if (nfq_set_verdict(qh, id, NF_DROP, 0, NULL) < 0) {
				logit("nfqueue_cb: Warning: nfq_set_verdict failed. id=%i, errno=%i (%s)\n", id, errno, strerror(errno));
			}
			return 0;
		}
		l4_header_start = (iph->ihl*4);
		saddr = &iph->saddr;
		daddr = &iph->daddr;
	}
	else if (ip_version == 6) {
		iph6 = (struct ipv6hdr *) full_packet;
		iph = NULL;
		if (iph6->nexthdr == IPPROTO_TCP || iph6->nexthdr == IPPROTO_UDP) {
			// TODO; handle more optional headers
			ip_protocol = iph6->nexthdr;
			l4_header_start = sizeof(struct ipv6hdr);
		}
		else {
			logit("nfqueue_cb: Error: IPv6 packet next header is not (TCP|UDP). Silently dropping packet. nexthdr=%i\n", iph6->nexthdr);
			if (nfq_set_verdict(qh, id, NF_DROP, 0, NULL) < 0) {
				logit("nfqueue_cb: Warning: nfq_set_verdict failed. id=%i, errno=%i (%s)\n", id, errno, strerror(errno));
			}
			return 0;
		}
		saddr = &iph6->saddr;
		daddr = &iph6->daddr;
	}
	else {
		logit("nfqueue_cb: Error: got non-IPv4/non-IPv6 packet! Silently dropping packet. (ip_version=%i)\n", ip_version);
		if (nfq_set_verdict(qh, id, NF_DROP, 0, NULL) < 0) {
			logit("nfqueue_cb: Warning: nfq_set_verdict failed. id=%i, errno=%i (%s)\n", id, errno, strerror(errno));
		}
		return 0;
	}

#ifdef DEBUG_LOG
	// Print out metatdata.
	logit("hw_protocol = 0x%04x hook = %u id = %u\n", ntohs(ph->hw_protocol), ph->hook, id);
	logit("Source IP: %s   Destination IP: %s\n", inet_ntop(ip_version == 4 ? AF_INET : AF_INET6, saddr, src_ip_str, sizeof(src_ip_str)), inet_ntop(ip_version == 4 ? AF_INET : AF_INET6, daddr, dst_ip_str, sizeof(dst_ip_str)));
	if (ip_protocol == IPPROTO_TCP) {
		if (size < (l4_header_start + 20) ) {
			logit("nfqueue_cb: Error: packet size is smaller than minimum TCP header. Silently dropping packet. l4_header_start=%i. size=%i\n", l4_header_start, size);
			if (nfq_set_verdict(qh, id, NF_DROP, 0, NULL) < 0) {
				logit("nfqueue_cb: Warning: nfq_set_verdict failed. id=%i, errno=%i (%s)\n", id, errno, strerror(errno));
			}
			return 0;
		}
		tcph = (struct tcphdr *) (full_packet + l4_header_start);

		logit("  TCP: src port=%i  dst port=%i%s%s%s%s%s%s\n", ntohs(tcph->source), ntohs(tcph->dest)
			, tcph->fin ? "  FIN" : ""
			, tcph->syn ? "  SYN" : ""
			, tcph->rst ? "  RST" : ""
			, tcph->psh ? "  PSH" : ""
			, tcph->ack ? "  ACK" : ""
			, tcph->urg ? "  URG" : ""
			);
	}
	else if (ip_protocol == IPPROTO_UDP) {
		if (size < (l4_header_start + 8) ) {
			logit("nfqueue_cb: Error: packet size is smaller than minimum UDP header. Silently dropping packet. l4_header_start=%i. size=%i\n", l4_header_start, size);
			if (nfq_set_verdict(qh, id, NF_DROP, 0, NULL) < 0) {
				logit("nfqueue_cb: Warning: nfq_set_verdict failed. id=%i, errno=%i (%s)\n", id, errno, strerror(errno));
			}
			return 0;
		}
		udph = (struct udphdr *) (full_packet + l4_header_start);

		logit("  UDP: src port=%i  dst port=%i\n", ntohs(udph->source), ntohs(udph->dest));
	}
	else {
		logit("Unexpected protocol: %i\n", ip_protocol);
	}
	
	// Print out packet in hex.
	logit_buffer(full_packet, size);
#endif

//uint64 GetPacketQueryID(struct packet *p)
//int AskIdent2(uint8 LocalOrRemote, uint64 queryID, uint8 protocol, uint32 lIP, uint16 lPort, uint32 rIP, uint16 rPort, uint32 tcp_states)
	if (ip_protocol == IPPROTO_TCP || ip_protocol == IPPROTO_UDP) {
		struct packet * np = NULL;
		int SendLocalQuestion = 1;

		// we're gonna hang onto this packet a while, add it to our tracking list...
		if ((np = newpacket(id, full_packet, size)) == NULL) {
			logit("nfqueue_cb: Fatal Error: newpacket() returned NULL. errno=%i (%s)\n", errno, strerror(errno));
			if (nfq_set_verdict(qh, id, NF_DROP, 0, NULL) < 0) {
				logit("nfqueue_cb: Warning: nfq_set_verdict failed. id=%i, errno=%i (%s)\n", id, errno, strerror(errno));
			}
			gRunServer = 0; // crash and burn
			return -1;
		}
		np->ip_version = ip_version;
		np->protocol = ip_protocol;
		memcpy(&np->saddr, saddr, ip_version == 4 ? 4 : 16);
		memcpy(&np->daddr, daddr, ip_version == 4 ? 4 : 16);

		if (ip_protocol == IPPROTO_TCP) {
			if (size < (l4_header_start + 20) ) {
				logit("nfqueue_cb: Error: packet size is smaller than minimum TCP header. l4_header_start=%i. size=%i\n", l4_header_start, size);
				DropPacket(qh, &np); np = NULL;
				return 0;
			}
			tcph = (struct tcphdr *) (full_packet + l4_header_start);

			np->sport = ntohs(tcph->source);
			np->dport = ntohs(tcph->dest);

			if (nfq_get_uid(nfad, &np->local_uid)) {
#ifdef DEBUG_LOG
				logit("nfq_get_uid returned uid=%i, setting have_local_answer=1\n", np->local_uid);
#endif
				np->have_local_answer = 1;
				if (nfq_get_gid(nfad, &np->local_gid)) {
#ifdef DEBUG_LOG
					logit("nfq_get_gid returned gid=%i, setting have_local_answer=2 and calling MakeDecisionOnPacket\n", np->local_gid);
#endif
					np->have_local_answer = 2;
					SendLocalQuestion = 0;
					if (MakeDecisionOnPacket(qh, np, OP_QueryLocalConnectionResponse))
						return 0;
				}
#ifdef DEBUG_LOG
				else {
					logit("nfq_get_gid returned zero.\n");
				}
#endif
			}
#ifdef DEBUG_LOG
			else {
				logit("nfq_get_uid returned zero.\n");
			}
#endif
			if (CheckDelayRemoteQuery(ip_version, IPPROTO_TCP, daddr, ntohs(tcph->dest))) {
				np->have_remote_answer = -2;
			}
			else {
				uint32 tcpstates = (tcph->syn && !tcph->ack) ? NETIDD_TCPFLAGS_REMOTE : NETIDD_TCPFLAGS_NOSYN;
				if (AskIdent2(IDENT2_REMOTE, GetPacketQueryID(np), ip_version, IPPROTO_TCP, saddr, ntohs(tcph->source), daddr, ntohs(tcph->dest), tcpstates) != 0) {
					logit("nfqueue_cb: Error: AskIdent2() failed, silent dropping packet. errno=%i (%s)\n", errno, strerror(errno));
					DropPacket(qh, &np); np = NULL;
					return 0;
				}
			}
			if (SendLocalQuestion) {
				// kernel inet_diag.c has two lookups: one for (TCPF_LISTEN | TCPF_SYN_RECV) and a seperate one for all other flags
				uint32 tcpstates = (tcph->syn && !tcph->ack) ? NETIDD_TCPFLAGS_LOCAL : NETIDD_TCPFLAGS_NOSYN;
				if (AskIdent2(IDENT2_LOCAL, GetPacketQueryID(np), ip_version, IPPROTO_TCP, daddr, ntohs(tcph->dest), NULL, 0, tcpstates) != 0) {
					logit("nfqueue_cb: Error: AskIdent2() failed, silent dropping packet. errno=%i (%s)\n", errno, strerror(errno));
					DropPacket(qh, &np); np = NULL;
					return 0;
				}
			}
		}
		else if (ip_protocol == IPPROTO_UDP) {
			if (size < (l4_header_start + 8) ) {
				logit("nfqueue_cb: Error: packet size is smaller than minimum UDP header. l4_header_start=%i. size=%i\n", l4_header_start, size);
				DropPacket(qh, &np); np = NULL;
				return 0;
			}
			udph = (struct udphdr *) (full_packet + l4_header_start);

			np->sport = ntohs(udph->source);
			np->dport = ntohs(udph->dest);

			if (nfq_get_uid(nfad, &np->local_uid)) {
#ifdef DEBUG_LOG
				logit("nfq_get_uid returned uid=%i, setting have_local_answer=1\n", np->local_uid);
#endif
				np->have_local_answer = 1;
				if (nfq_get_gid(nfad, &np->local_gid)) {
#ifdef DEBUG_LOG
					logit("nfq_get_gid returned gid=%i, setting have_local_answer=2 and calling MakeDecisionOnPacket\n", np->local_gid);
#endif
					np->have_local_answer = 2;
					SendLocalQuestion = 0;
					if (MakeDecisionOnPacket(qh, np, OP_QueryLocalConnectionResponse))
						return 0;
				}
			}
			if (AskIdent2(IDENT2_REMOTE, GetPacketQueryID(np), ip_version, IPPROTO_UDP, saddr, ntohs(udph->source), daddr, ntohs(udph->dest), 0) != 0) {
				logit("nfqueue_cb: Error: AskIdent2() failed, silent dropping packet. errno=%i (%s)\n", errno, strerror(errno));
				DropPacket(qh, &np); np = NULL;
				return 0;
			}
			if (SendLocalQuestion) {
				if (AskIdent2(IDENT2_LOCAL, GetPacketQueryID(np), ip_version, IPPROTO_UDP, daddr, ntohs(udph->dest), saddr, ntohs(udph->source), 0) != 0) {
					logit("nfqueue_cb: Error: AskIdent2() failed, silent dropping packet. errno=%i (%s)\n", errno, strerror(errno));
					DropPacket(qh, &np); np = NULL;
					return 0;
				}
			}
		}
	}
	else {
		logit("Received packet with unexpected IP protocol, silent drop. src=%s, dst=%s, proto=%i\n", inet_ntop(ip_version == 4 ? AF_INET : AF_INET6, saddr, src_ip_str, sizeof(src_ip_str)), inet_ntop(ip_version == 4 ? AF_INET : AF_INET6, daddr, dst_ip_str, sizeof(dst_ip_str)), ip_protocol);
		if (nfq_set_verdict(qh, id, NF_DROP, 0, NULL) < 0) {
			logit("nfqueue_cb: Warning: nfq_set_verdict failed. id=%i, errno=%i (%s)\n", id, errno, strerror(errno));
		}
		return 0;
	}
	
	return 0;
}

uint16 calcsum(void* in_buf, uint16 length) {
	uint32 sum = 0;
	uint16 *buffer = (uint16*) in_buf;

	for (; length>1; length-=2)
		sum += *buffer++;

	if (length==1)
		sum += (char)*buffer;

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return ~sum;
}

// Send a ICMP Destination Unreachable
// - Reject uses ICMP_PKT_FILTERED (Code 13: Admin Prohibited)
// - Refuse uses ICMP_PORT_UNREACH (Code 3: Port Unreachable)
int send_icmp4_dst_unreachable(uint8* packet, uint32 size, uint8 icmp_code) {
	struct iphdr * oiph = NULL, *niph = NULL;
	struct icmphdr * icmph = NULL;
	struct sockaddr_in dstaddr;
	uint8*	icmpdata = NULL;
	uint8	buf[128]; // 20 bytes IP header, 8 bytes ICMP header, 20-32 bytes orig IP header, 8 bytes orig data
	uint32	outsize = 0, opacket_size_to_send;

	if (icmp_sock == -1) {
		logit("send_icmp4_dst_unreachable: Error: icmp_sock not open\n");
		errno = -EBADF;
		return -1;
	}

	if (size < 20) {
		logit("send_icmp4_dst_unreachable: Error: packet size is smaller than minimum IP header. size=%i\n", size);
		errno = -EINVAL;
		return -1;
	}
	oiph = (struct iphdr *) packet;
	if (oiph->ihl < 5) {
		logit("send_icmp4_dst_unreachable: Error: original packet IP header size is smaller than possible. (oiph->ihl=%i) * 4. size=%i\n", oiph->ihl, size);
		logit_buffer(packet, size);
		errno = -EINVAL;
		return -1;
	}
	if (size < (oiph->ihl*4)) {
		logit("send_icmp4_dst_unreachable: Error: original packet size is smaller than claimed IP header length. (oiph->ihl=%i) * 4. size=%i\n", oiph->ihl, size);
		errno = -EINVAL;
		return -1;
	}
	opacket_size_to_send = (oiph->ihl*4) + 8;
	#ifdef DEBUG_LOG
		logit("send_icmp4_dst_unreachable: DEBUG: opacket_size_to_send=%i. (oiph->ihl=%i) * 4. size=%i\n", opacket_size_to_send, oiph->ihl, size);
	#endif

	if (size < opacket_size_to_send) {
		logit("send_icmp4_dst_unreachable: Error: original packet size is smaller than the amount we want to send (IP header + 8 bytes). (oiph->ihl=%i) * 4. size=%i\n", oiph->ihl, size);
		errno = -EINVAL;
		return -1;
	}

	outsize = 20 + 8 + opacket_size_to_send;

	if (outsize > sizeof(buf)) {
		logit("send_icmp4_dst_unreachable: calculated outsize is bigger than buffer? Should never happen!\n");
		errno = -ENOMEM;
		return -1;
	}

	memset(buf, 0, sizeof(buf));
	niph = (struct iphdr *) buf;
	niph->version = 4;
	niph->ihl = 5;
	niph->tos = 0;
	niph->tot_len = outsize;
	niph->ttl = 255;
	niph->protocol = 1; // ICMP
	niph->saddr = oiph->daddr;
	niph->daddr = oiph->saddr; // return to sender
	niph->check = calcsum(niph, niph->ihl * 4);

	icmph = (struct icmphdr *) (buf + 20);
	icmph->type = ICMP_DEST_UNREACH;
	icmph->code = icmp_code;
	icmpdata = buf + (20 + 8); // our IP header=20 bytes, ICMP header = 8 bytes
	memcpy(icmpdata, packet, opacket_size_to_send);
	icmph->checksum = calcsum(icmph, 8 + opacket_size_to_send);

	dstaddr.sin_family = AF_INET;
	dstaddr.sin_addr.s_addr = niph->daddr;
	if (sendto(icmp_sock, buf, outsize, 0, (struct sockaddr *) &dstaddr, sizeof(struct sockaddr)) < 0) {
		logit("send_icmp4_dst_unreachable: sendto failed. errno=%i (%s)\n", errno, strerror(errno));
		return -1;
	}
#ifdef DEBUG_LOG
	logit("Sent ICMP Dst Unreachable reply: %i bytes\n", outsize);
	logit_buffer(buf, outsize);
#endif
	return 0;
}

#if LINUX45
struct ipv6_psudo_hdr {
	uint8	saddr[16];
	uint8	daddr[16];
	uint32	size;
	uint8	zeros[3];
	uint8	protocol;
};

// Send a ICMPv6 Destination Unreachable
// - Reject uses ICMPV6_ADM_PROHIBITED (Code 1: Admin Prohibited)
// - Refuse uses ICMPV6_PORT_UNREACH (Code 4: Port Unreachable)
int send_icmp6_dst_unreachable(uint8* packet, uint32 size, uint8 icmp_code) {
	struct ipv6_psudo_hdr * piph6 = NULL;
	struct ipv6hdr * oiph6 = NULL, *niph6 = NULL;
	struct icmp6hdr * icmph6 = NULL;
	struct sockaddr_in6 dstaddr;
	uint8*	icmpdata = NULL;
	uint8	buf[IPV6_MIN_MTU]; // RFC says send as much of original packet as possible up to IPV6_MIN_MTU total size of ICMP packet
	uint32	outsize, opacket_size_to_send;

	if (icmp6_sock == -1) {
		logit("send_icmp6_dst_unreachable: Error: icmp6_sock not open\n");
		errno = -EBADF;
		return -1;
	}

	if (size < 40) {
		logit("send_icmp6_dst_unreachable: Error: packet size is smaller than minimum IP header. size=%i\n", size);
		errno = -EINVAL;
		return -1;
	}
	oiph6 = (struct ipv6hdr *) packet;
	opacket_size_to_send = (IPV6_MIN_MTU - sizeof(struct ipv6hdr) - sizeof(struct icmp6hdr)) > size ? size : (IPV6_MIN_MTU - sizeof(struct ipv6hdr) - sizeof(struct icmp6hdr));
	outsize = sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr) + opacket_size_to_send;

	memset(buf, 0, sizeof(buf));
	piph6 = (struct ipv6_psudo_hdr *) buf;
	piph6->size = sizeof(struct icmp6hdr) + opacket_size_to_send;
	piph6->protocol = IPPROTO_ICMPV6;
	memcpy(&piph6->saddr, &oiph6->daddr, sizeof(piph6->saddr));
	memcpy(&piph6->daddr, &oiph6->saddr, sizeof(piph6->saddr)); // return to sender

	icmph6 = (struct icmp6hdr *) buf + sizeof(struct ipv6hdr);
	icmph6->icmp6_type = ICMPV6_DEST_UNREACH;
	icmph6->icmp6_code = icmp_code;

	icmpdata = buf + sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr);
	memcpy(icmpdata, packet, opacket_size_to_send);
	icmph6->icmp6_cksum = calcsum(buf, outsize);

	memset(buf, 0, sizeof(struct ipv6hdr));
	niph6 = (struct ipv6hdr *) buf;
	niph6->version = 6;
	niph6->payload_len = sizeof(struct icmp6hdr) + opacket_size_to_send;
	niph6->nexthdr = IPPROTO_ICMPV6;
	niph6->hop_limit = 255;
	memcpy(&niph6->saddr, &oiph6->daddr, sizeof(niph6->saddr));
	memcpy(&niph6->daddr, &oiph6->saddr, sizeof(niph6->saddr)); // return to sender

	memset(&dstaddr, 0, sizeof(dstaddr));
	dstaddr.sin6_family = AF_INET6;
	//dstaddr.sin6_port = IPPROTO_ICMPV6;
	dstaddr.sin6_port = 0;
	dstaddr.sin6_flowinfo = 0;
	memcpy(dstaddr.sin6_addr.s6_addr, &niph6->daddr, sizeof(dstaddr.sin6_addr.s6_addr));
	if (sendto(icmp6_sock, buf, outsize, 0, (struct sockaddr *) &dstaddr, sizeof(dstaddr)) < 0) {
		logit("send_icmp6_dst_unreachable: sendto failed. errno=%i (%s)\n", errno, strerror(errno));
		return -1;
	}
#ifdef DEBUG_LOG
	logit("Sent ICMPv6 Dst Unreachable reply: %i bytes\n", outsize);
	logit_buffer(buf, outsize);
#endif
	return 0;
}
#else
// Send a ICMPv6 Destination Unreachable
// - Reject uses ICMPV6_ADM_PROHIBITED (Code 1: Admin Prohibited)
// - Refuse uses ICMPV6_PORT_UNREACH (Code 4: Port Unreachable)
int send_icmp6_dst_unreachable(uint8* packet, uint32 size, uint8 icmp_code) {
	struct ipv6hdr * oiph6 = NULL;
	struct icmp6hdr * icmph6 = NULL;
	struct sockaddr_in6 dstaddr;
	uint8*	icmpdata = NULL;
	uint8	buf[IPV6_MIN_MTU]; // RFC says send as much of original packet as possible up to IPV6_MIN_MTU total size of ICMP packet
	uint32	outsize, opacket_size_to_send;

	if (icmp6_sock == -1) {
		logit("send_icmp6_dst_unreachable: Error: icmp6_sock not open\n");
		errno = -EBADF;
		return -1;
	}

	if (size < 40) {
		logit("send_icmp6_dst_unreachable: Error: packet size is smaller than minimum IP header. size=%i\n", size);
		errno = -EINVAL;
		return -1;
	}
	oiph6 = (struct ipv6hdr *) packet;
	opacket_size_to_send = (IPV6_MIN_MTU - sizeof(struct ipv6hdr) - sizeof(struct icmp6hdr)) > size ? size : (IPV6_MIN_MTU - sizeof(struct ipv6hdr) - sizeof(struct icmp6hdr));
	outsize = sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr) + opacket_size_to_send;

	memset(buf, 0, sizeof(buf));
	icmph6 = (struct icmp6hdr *) buf;
	icmph6->icmp6_type = ICMPV6_DEST_UNREACH;
	icmph6->icmp6_code = icmp_code;

	icmpdata = buf + sizeof(struct icmp6hdr);
	memcpy(icmpdata, packet, opacket_size_to_send);
	icmph6->icmp6_cksum = calcsum(buf, outsize);

	memset(&dstaddr, 0, sizeof(dstaddr));
	dstaddr.sin6_family = AF_INET6;
	dstaddr.sin6_port = 0;
	dstaddr.sin6_flowinfo = 0;
	memcpy(dstaddr.sin6_addr.s6_addr, &oiph6->saddr, sizeof(dstaddr.sin6_addr.s6_addr));
	if (sendto(icmp6_sock, buf, outsize, 0, (struct sockaddr *) &dstaddr, sizeof(dstaddr)) < 0) {
		logit("send_icmp6_dst_unreachable: sendto failed. errno=%i (%s)\n", errno, strerror(errno));
		return -1;
	}
#ifdef DEBUG_LOG
	logit("Sent ICMPv6 Dst Unreachable reply: %i bytes\n", outsize);
	logit_buffer(buf, outsize);
#endif
	return 0;
}
#endif

int send_icmp_admin_prohibited(uint8 ip_version, uint8* packet, uint32 size) {
	if (ip_version == 4)
		return send_icmp4_dst_unreachable(packet, size, ICMP_PKT_FILTERED);
	else if (ip_version == 6)
		return send_icmp6_dst_unreachable(packet, size, ICMPV6_ADM_PROHIBITED);
	return -1;
}

int send_icmp_port_unreachable(uint8 ip_version, uint8* packet, uint32 size) {
	if (ip_version == 4)
		return send_icmp4_dst_unreachable(packet, size, ICMP_PORT_UNREACH);
	else if (ip_version == 6)
		return send_icmp6_dst_unreachable(packet, size, ICMPV6_PORT_UNREACH);
	return -1;
}

int CheckDelayRemoteQuery(uint8 ip_version, uint8 protocol, void* localIP, uint16 localport) {
	struct DelayRemoteQueryCache *prev = NULL, *cur = NULL;
	uint64 tsnow = GetTS();

	for (cur = drqchead; cur; prev = cur, cur = (cur ? cur->next : NULL)) {
		if ((tsnow - cur->ts) > 10000) {
			if (prev)
				prev->next = cur->next;
			else
				drqchead = cur->next;
			free(cur);
			cur = prev;
			continue;
		}
		if (cur->ip_version == ip_version && cur->protocol == protocol && memcmp(cur->localIP, localIP, ip_version == 4 ? 4 : 16) == 0 && cur->localport == localport)
			return 1;
	}
	return 0;
}

void AddDelayRemoteQuery(uint8 ip_version, uint8 protocol, void* localIP, uint16 localport) {
	struct DelayRemoteQueryCache *prev = NULL, *cur = NULL;
	uint64 tsnow = GetTS();
	int addit = 1;

	for (cur = drqchead; cur; prev = cur, cur = (cur ? cur->next : NULL)) {
		if (cur->ip_version == ip_version && cur->protocol == protocol && memcmp(cur->localIP, localIP, ip_version == 4 ? 4 : 16) == 0 && cur->localport == localport) {
			cur->ts = tsnow;
			addit = 0;
			// continue the loop to check for expired entries
		}
		else if ((tsnow - cur->ts) > 10000) {
			if (prev)
				prev->next = cur->next;
			else
				drqchead = cur->next;
			free(cur);
			cur = prev;
			continue;
		}
	}
	if (addit) {
		if ((cur = malloc(sizeof(struct DelayRemoteQueryCache))) == NULL)
			return;
		cur->ts = tsnow;
		cur->ip_version = ip_version;
		cur->protocol = protocol;
		memcpy(cur->localIP, localIP, ip_version == 4 ? 4 : 16);
		cur->localport = localport;
		cur->next = drqchead;
		drqchead = cur;
	}
}
