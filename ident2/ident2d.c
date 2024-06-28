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
#define BUILD_ident2d
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
#include <dirent.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <linux/securebits.h>
#include <sys/epoll.h>
#include <pthread.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "ident2d.h"
#include "tcp_states.h"

#define IsLocalHost(v, i) ((v == 4 && ((*((uint32*) i)) & 0x000000FF) == 0x0000007F) || (v == 6 && memcmp(i, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1", 16) == 0))

// globals
volatile int gRunServer = 1;
volatile int gInitComplete = 0;
int epfd = -1;
int gShutdownPipe[2] = { -1, -1 };
pthread_t *threadIDs = NULL;
pthread_mutex_t clientlist_mutex; // hold for modifying clienthead, any client::next or client::prev, or nextClientID
struct client *clienthead = NULL;
uint64 nextClientID = 0;
int peer_sock = -1;
int client_sock = -1;
int precache_sock = -1;
struct ident2d_config_struct config;

int RecvClient(struct epoll_event *ev, struct client *c);
void RecvPrecacheClient(struct client *c);
int RecvUDP(int s, struct epoll_event *ev);
void* thread_func(void* arg);
int RearmEpoll(struct epoll_event *ev);
void ShutdownThreads();
#define atomic_inc(v) (__sync_add_and_fetch((int*) &v, 1))
#define atomic_dec(v) (__sync_sub_and_fetch((int*) &v, 1))

// functions
void SigHandler(int sig) {
	switch (sig) {
		case SIGINT:
		case SIGTERM:
			#ifdef DEBUG_LOG
				logit("DEBUG: Caught SIGTERM/SIGINT.\n");
			#endif
			ShutdownThreads();
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

void dispose_fds(int* fds, int count) {
	int x;
	for (x=0; x<count; x++)
		close(fds[x]);
}

void removeclient(struct client *c) {
	pthread_mutex_lock(&clientlist_mutex);
	
	if (c->prev == NULL && c->next == NULL && clienthead != c) {
		pthread_mutex_unlock(&clientlist_mutex);
		return;
	}
	
	if (c->next)
		c->next->prev = c->prev;
	if (c->prev)
		c->prev->next = c->next;
	if (clienthead == c)
		clienthead = c->next;
	c->prev = c->next = NULL;
	if (shutdown(c->s, SHUT_RDWR) < 0) {
		logit("removeclient: shutdown() failed. errno=%i (%s)\n", errno, strerror(errno));
	}

	pthread_mutex_unlock(&clientlist_mutex);

	if (atomic_dec(c->refcount) == 0) {
		#ifdef DEBUG_LOG
			logit("DEBUG: removeclient: c->refcount hit zero, deleting and closing socket. (fd=%i) (id=%lld)\n", c->s, c->id);
		#endif
		close(c->s);
		free(c);
	}
}

// caller must hold ONESHOT for the socket
void RemoveClientFromEPoll(struct client *c) {
	if (epoll_ctl(epfd, EPOLL_CTL_DEL, c->s, NULL) < 0) {
		logit("RemoveClientFromEPoll: epoll_ctl(EPOLL_CTL_DELL, c->s) failed. errno=%i (%s)\n", errno, strerror(errno));
		ShutdownThreads();
	}
	removeclient(c);

	if (atomic_dec(c->refcount) == 0) {
		#ifdef DEBUG_LOG
			logit("DEBUG: RemoveClientFromEPoll: c->refcount hit zero, deleting and closing socket. (fd=%i) (id=%lld)\n", c->s, c->id);
		#endif
		close(c->s);
		free(c);
	}
}

void RemovePrecacheClient(struct client *c) {
	if (epoll_ctl(epfd, EPOLL_CTL_DEL, c->s, NULL) < 0) {
		logit("RemovePrecacheClient: epoll_ctl(EPOLL_CTL_DELL, c->s) failed. errno=%i (%s)\n", errno, strerror(errno));
		ShutdownThreads();
	}

	close(c->s);
	free(c);
}

int newclient(uint8 type, int ns) {
	struct client *nc;
	struct epoll_event ev;

	if ((nc = (struct client *) malloc(sizeof(struct client))) == NULL)
		return -1;
	memset(nc, 0, sizeof(struct client));

	nc->type = type;
	nc->s = ns;
	nc->refcount = 1; // one for epoll

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLONESHOT;
	ev.data.ptr = nc;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, nc->s, &ev) < 0) {
		logit("newclient: Error: epoll_ctl(EPOLL_CTL_ADD, nc->s) failed. errno=%i (%s)\n", errno, strerror(errno));
		return -1;
	}
	
	if (type == CLIENTYPE_CLIENT) {
		nc->refcount++; // another client list
		pthread_mutex_lock(&clientlist_mutex);

		nc->id = ++nextClientID;

		if (clienthead)
			clienthead->prev = nc;
		nc->next = clienthead;
		clienthead = nc;

		pthread_mutex_unlock(&clientlist_mutex);
	}

	#ifdef DEBUG_LOG
		logit("DEBUG: newclient: new client created (type=%i) (fd=%i) (id=%lld).\n", type, nc->s, nc->id);
	#endif

	return 0;
}

void usage() {
	fprintf(stdout, "Usage: ident2d [options]\n");
	fprintf(stdout, " -v, --version    print version and exit\n");
	fprintf(stdout, " -d, --debug      run in debug mode (no daemonize, log to screen)\n");
	fprintf(stdout, " -f <filename>    use <filename> as config file\n");
}

int main(int argc, char **argv) {
	const char* config_file = IDENT2D_CONFIG;
	int retval = EXIT_FAILURE;
	socklen_t len;
	struct sockaddr_un addr;
	int nodaemon = 0;
	struct sockaddr_in6 udpsockaddr;
	struct passwd *pwd = NULL;
	struct group *grp = NULL;
	cap_t caps;
	cap_value_t kept_caps[] = {
		CAP_DAC_READ_SEARCH, // traverse into /proc/##/ with grsec
		CAP_SYS_PTRACE, // reading /proc/#/fd/# symlink target requires SYS_TRACE
	};
	struct epoll_event ev;
	int select_nfds;
	int on = 1;

	for (int x=1; x<argc; x++) {
		if (strcmp(argv[x], "-d") == 0 || strcmp(argv[x], "--debug") == 0)
			nodaemon = 1;
		else if (strcmp(argv[x], "-v") == 0 || strcmp(argv[x], "--version") == 0) {
			fprintf(stdout, "ident2d: no version scheme yet...\n");
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
	if (config.SocketGroup[0]) {
		if ((grp = getgrnam(config.SocketGroup)) == NULL) {
			fprintf(stderr, "Error: unable to find gid for group '%s'\n", config.SocketGroup);
			goto cleanup;
		}
	}
	if (config.NumThreads <= 0 || config.NumThreads > 4096) {
		fprintf(stderr, "Error: number of threads set to invalid value: %i\n", config.NumThreads);
		goto cleanup;
	}

	umask(0077); // default permissions max: rwx-------

	//fprintf(stderr, "ident2d starting up: Using socket path: %s\n", IDENT2_SOCKNAME);
	if (nodaemon) {
		fprintf(stderr, "Running interactively by request...\n");
		signal(SIGTERM, &SigHandler); // catch TERM signal
		signal(SIGINT, &SigHandler); // catch SIGINT signal
	}
	else {
		daemonize(PIDFILE);
		if (openlog(LOGFILE) != 0)
			goto cleanup;
		logit("ident2d starting up: Using socket path: %s\n", IDENT2_SOCKNAME);
	}

	// open client socket...
	if ((client_sock = socket(PF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) == -1) {
		logit("socket(client_sock) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, IDENT2_SOCKNAME);
	len = strlen(addr.sun_path) + sizeof(addr.sun_family);
	unlink(IDENT2_SOCKNAME);
	if (bind(client_sock, (struct sockaddr *) &addr, len) == -1) {
		logit("bind(client_sock) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	if (pwd || grp) {
		if (chown(IDENT2_SOCKNAME, pwd ? pwd->pw_uid : -1 , (grp ? grp->gr_gid : pwd->pw_gid) ) != 0) { // chown it so we can unlink it as we shut down
			logit("chown(client_sock) failed. errno=%i (%s)\n", errno, strerror(errno));
			goto cleanup;
		}
	}
	if (chmod(IDENT2_SOCKNAME, (config.SocketOther == 1 ? 0777 : 0770) ) != 0) {
		logit("chmod(client_sock) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	#ifdef DEBUG_LOG
	// turn on credential passing (allowed on listening socket since Kernel 3.10)
	if (setsockopt(client_sock, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) != 0) {
		logit("setsockopt(client_sock, SO_PASSCRED) failed. errno=%i (%s)\n", errno, strerror(errno));
		return -1;
	}
	#endif
	
	// open cache notify socket
	if (config.AllowPrecache) {
		if ((precache_sock = socket(PF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) == -1) {
			logit("socket(precache_sock) failed. errno=%i (%s)\n", errno, strerror(errno));
			goto cleanup;
		}
	
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		strcpy(addr.sun_path, IDENT2PRECACHE_SOCKNAME);
		len = strlen(addr.sun_path) + sizeof(addr.sun_family);
		unlink(IDENT2PRECACHE_SOCKNAME);
		if (bind(precache_sock, (struct sockaddr *) &addr, len) == -1) {
			logit("bind(precache_sock) failed. errno=%i (%s)\n", errno, strerror(errno));
			goto cleanup;
		}
		if (pwd || grp) {
			if (chown(IDENT2PRECACHE_SOCKNAME, pwd ? pwd->pw_uid : -1 , (grp ? grp->gr_gid : pwd->pw_gid) ) != 0) { // chown it so we can unlink it as we shut down
				logit("chown(precache_sock) failed. errno=%i (%s)\n", errno, strerror(errno));
				goto cleanup;
			}
		}
		if (chmod(IDENT2PRECACHE_SOCKNAME, 0777 ) != 0) {
			logit("chmod(precache_sock) failed. errno=%i (%s)\n", errno, strerror(errno));
			goto cleanup;
		}
		// turn on credential passing (allowed on listening socket since Kernel 3.10)
		if (setsockopt(precache_sock, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) != 0) {
			logit("setsockopt(precache_sock, SO_PASSCRED) failed. errno=%i (%s)\n", errno, strerror(errno));
			return -1;
		}
	}

	// open udp socket
	if ((peer_sock = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) == -1) {
		logit("socket(peer_sock) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	memset(&udpsockaddr, 0, sizeof(udpsockaddr));
	udpsockaddr.sin6_family = AF_INET6;
	udpsockaddr.sin6_port = htons(config.UDPPort);
	//memset(udpsockaddr.sin6_addr.s_addr, 0, 16); // already done by original memset
	if (bind(peer_sock, &udpsockaddr, sizeof(udpsockaddr)) == -1) {
		logit("bind(peer_sock, port=%i) failed. errno=%i\n", config.UDPPort, errno);
		goto cleanup;
	}

	// open netlink socket
	if (open_netlink_socket() != 0) {
		fprintf(stderr, "open_netlink_socket failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	// Turn on keep caps and turn off cap escalations
	if (prctl(PR_SET_KEEPCAPS, 1) != 0) {
		logit("prctl(PR_SET_KEEPCAPS, 1) failed. errno=%i (%s)\n", errno, strerror(errno));
//	if (prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_NOROOT | SECBIT_NOROOT_LOCKED) != 0) {
//		logit("prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_NOROOT | SECBIT_NOROOT_LOCKED) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
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
		goto cleanup;
	}
	if (cap_clear(caps) != 0) {
		logit("cap_clear() failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	if (cap_set_flag(caps, CAP_EFFECTIVE, sizeof(kept_caps)/sizeof(cap_value_t), kept_caps, CAP_SET) != 0) {
		logit("cap_set_flag(CAP_EFFECTIVE) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	if (cap_set_flag(caps, CAP_PERMITTED, sizeof(kept_caps)/sizeof(cap_value_t), kept_caps, CAP_SET) != 0) {
		logit("cap_set_flag(CAP_PERMITTED) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	if (cap_set_proc(caps) != 0) {
		logit("cap_set_proc()[1] failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	cap_free(caps);

	// Setup listening sockets
	if (listen(client_sock, 5) == -1) {
		logit("listen(client_sock) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	if (precache_sock != -1) {
		if (listen(precache_sock, 5) == -1) {
			logit("listen(precache_sock) failed. errno=%i (%s)\n", errno, strerror(errno));
			goto cleanup;
		}
	}

	// set up epoll
	if ((epfd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
		logit("Error: epoll_create1 failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	// peer sock
	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLONESHOT;
	ev.data.ptr = malloc(sizeof(struct client));
	memset(ev.data.ptr, 0, sizeof(struct client));
	((struct client *) ev.data.ptr)->type = CLIENTYPE_PEERSOCK;
	((struct client *) ev.data.ptr)->s = peer_sock;
	((struct client *) ev.data.ptr)->refcount = 1;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, peer_sock, &ev) < 0) {
		logit("Error: epoll_ctl(EPOLL_CTL_ADD, peer_sock) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	if (pipe2(gShutdownPipe, O_CLOEXEC) != 0) {
		logit("Error: pipe2(gShutdownPipe) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	// Shutdown Pipe
	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLONESHOT;
	ev.data.ptr = malloc(sizeof(struct client));
	memset(ev.data.ptr, 0, sizeof(struct client));
	((struct client *) ev.data.ptr)->type = CLIENTYPE_SHUTDOWN;
	((struct client *) ev.data.ptr)->s = gShutdownPipe[0];
	((struct client *) ev.data.ptr)->refcount = 1;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, gShutdownPipe[0], &ev) < 0) {
		logit("Error: epoll_ctl(EPOLL_CTL_ADD, peer_sock) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	// init FindPIDFromSocketInode cache (create mutex)
	if (FindPIDFromSocketInode_initcache() != 0) {
		logit("Error: FindPIDFromSocketInode_initcache failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	// set up mutex
	if (pthread_mutex_init(&clientlist_mutex, NULL) != 0) {
		logit("Error: pthread_mutex_init for clientlist_mutex failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	// set up threads variable
	if ((threadIDs = malloc(sizeof(pthread_t) * (config.NumThreads+1))) == NULL) {
		logit("Error: malloc for threadIDs failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	// launch threads
	threadIDs[0] = pthread_self();
	for (int x=1; x<=config.NumThreads; x++) {
		pthread_create(&threadIDs[x], NULL, &thread_func, NULL);
	}

	daemonize(NULL); // second call - signal parent that we're done

	__sync_synchronize(); // full memory barrier before useing our volatile flag...
	gInitComplete = 1;

	// check for new client connections
	select_nfds = ((client_sock > precache_sock) ? client_sock : precache_sock) + 1;
	while (gRunServer) {
		int new_client_sock;
		fd_set fds_read, fds_except;

		FD_ZERO(&fds_read);
		FD_ZERO(&fds_except);
		FD_SET(client_sock, &fds_read);
		FD_SET(client_sock, &fds_except);
		if (precache_sock != -1) {
			FD_SET(precache_sock, &fds_read);
			FD_SET(precache_sock, &fds_except);
		}
		
		#ifdef DEBUG_LOG
			logit("DEBUG: starting select on client_sock and/or precache_sock.\n");
		#endif

		if (select(select_nfds, &fds_read, NULL, &fds_except, NULL) <= -1) {
			if (errno != EINTR) {
				logit("select(client_sock|precache_sock) errored. errno=%i (%s)\n", errno, strerror(errno));
				goto cleanup;
			}
			// interrupted, continue and let the check for gRunServer do it's thing
		}

		#ifdef DEBUG_LOG
			logit("DEBUG: select on listening sockets triggered.\n");
		#endif

		if (FD_ISSET(client_sock, &fds_read) || FD_ISSET(client_sock, &fds_except)) {
			#ifdef DEBUG_LOG
				logit("DEBUG: client_sock in select set, calling accept.\n");
			#endif
			if ((new_client_sock = accept4(client_sock, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC)) == -1) {
				if (errno == EWOULDBLOCK || errno == EAGAIN)
					continue;
				if (errno == ECONNABORTED)
					continue;
				logit("accept(client_sock) errored. errno=%i (%s)\n", errno, strerror(errno));
				goto cleanup;
			}
			if (newclient(CLIENTYPE_CLIENT, new_client_sock) != 0) {
				logit("newclient(CLIENTYPE_CLIENT) errored. errno=%i (%s)\n", errno, strerror(errno));
				goto cleanup;
			}
		}
		if (precache_sock != -1 && (FD_ISSET(precache_sock, &fds_read) || FD_ISSET(precache_sock, &fds_except))) {
			#ifdef DEBUG_LOG
				logit("DEBUG: precache_sock in select set, calling accept.\n");
			#endif
			while (1) {
				if ((new_client_sock = accept4(precache_sock, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC)) == -1) {
					if (errno == EWOULDBLOCK || errno == EAGAIN)
						break;
					if (errno == ECONNABORTED)
						break;
					logit("accept(precache_sock=%i) errored. errno=%i (%s)\n", precache_sock, errno, strerror(errno));
					goto cleanup;
				}
				if (newclient(CLIENTYPE_PRECACHE, new_client_sock) != 0) {
					logit("newclient(CLIENTYPE_PRECACHE) errored. errno=%i (%s)\n", errno, strerror(errno));
					goto cleanup;
				}
			}
		}
	}

	logit("reached end of main, beginning cleanup.\n");
	retval = 0;

cleanup:
	gRunServer = 0;

	if (threadIDs) {
		int thread_status = 0;
		ShutdownThreads();
		for (int x=1; x<=config.NumThreads; x++) {
			if (pthread_join(threadIDs[x], (void**) &thread_status) != 0) {
				retval = EXIT_FAILURE;
			}
			if (retval == 0 && thread_status != 0)
				retval = thread_status;
		}
		free(threadIDs);
		threadIDs = NULL;
	}
	
//	for (struct client *c = clienthead; c; c = c ? c->next : clienthead) {
//		removeclient(&c);
//	}

	pthread_mutex_destroy(&clientlist_mutex);

	FindPIDFromSocketInode_cleanup();

	if (client_sock != -1)
		close(client_sock);
	client_sock = -1;

	unlink(IDENT2_SOCKNAME);

	if (precache_sock != -1)
		close(precache_sock);
	precache_sock = -1;

	if (config.AllowPrecache)
		unlink(IDENT2PRECACHE_SOCKNAME);

	if (epfd != -1)
		close(epfd);
	epfd = -1;

	if (gShutdownPipe[0])
		close(gShutdownPipe[0]);
	gShutdownPipe[0] = -1;
	if (gShutdownPipe[1])
		close(gShutdownPipe[1]);
	gShutdownPipe[1] = -1;

	close_netlink_socket();

	logit("closing log, exiting.\n");
	closelog();

	return retval;
}

void ShutdownThreads() {
	char junk = 1;
	gRunServer = 0;
	if (client_sock != -1)
		shutdown(client_sock, SHUT_RDWR);
	if (write(gShutdownPipe[1], &junk, 1) != 1) {
		logit("ShutdownThreads: write errored. errno=%i (%s)\n", errno, strerror(errno));
	}
}

void* thread_func(void* arg) {
	struct epoll_event ev;
	int rv;
	struct client * c;

	#ifdef DEBUG_LOG
		logit("DEBUG: thread_func: thread started, waiting for init complete signal.\n");
	#endif

	while (!gInitComplete)
		usleep(25000); // 25ms

	#ifdef DEBUG_LOG
		logit("DEBUG: thread_func: init complete signaled, begining main loop.\n");
	#endif

	while (gRunServer) {
		if ((rv = epoll_wait(epfd, &ev, 1, -1)) != 1) {
			if (rv == -1 && errno == EINTR) {
				#ifdef DEBUG_LOG
					logit("DEBUG: thread_func: epoll_wait returned EINTR.\n");
				#endif
				continue; // continue to let gRunServer do it's thing
			}
			logit("Error: thread_func: epoll_wait errored. errno=%i (%s)\n", errno, strerror(errno));
			ShutdownThreads();
			return (void*) EXIT_FAILURE;
		}
		c = (struct client *) ev.data.ptr;
		#ifdef DEBUG_LOG
			logit("DEBUG: thread_func: epoll_wait returned events %08x for client (fd=%i) (type=%i) (id=%lld).\n", ev.events, c->s, c->type, c->id);
		#endif
		switch (c->type) {
			case CLIENTYPE_SHUTDOWN:
				if (RearmEpoll(&ev) != 0) {
					logit("Error: thread_func: RearmEpoll() on gShutdownPipe[0].\n");
					return (void*) EXIT_FAILURE;
				}
				continue; // continue while loop to let gRunServer do it's thing
			case CLIENTYPE_PEERSOCK:
				atomic_inc(c->refcount);
				if (ev.events & EPOLLIN) {
					if ((rv = RecvUDP(c->s, &ev)) < 0) {
						logit("Error: thread_func: RecvUDP returned failure.\n");
						ShutdownThreads();
						return (void*) EXIT_FAILURE;
					}
					if (rv)
						break;
				}
				if (ev.events & (~EPOLLIN)) {
					logit("Error: thread_func: socket error reported on peer_sock.\n");
					ShutdownThreads();
					return (void*) EXIT_FAILURE;
				}
				if (RearmEpoll(&ev) != 0) {
					logit("Error: thread_func: RearmEpoll() on unix domain socket listener.\n");
					ShutdownThreads();
					return (void*) EXIT_FAILURE;
				}
				break;
			case CLIENTYPE_CLIENT:
				atomic_inc(c->refcount);
				if (ev.events & EPOLLIN) {
					if ((rv = RecvClient(&ev, c)) < 0) {
						logit("Warning: thread_func: RecvClient returned failure, removing client. (fd=%i) (id=%lld)\n", c->s, c->id);
						RemoveClientFromEPoll(c);
						break;
					}
					if (rv)
						break;
				}
				if (ev.events & (~EPOLLIN)) {
					logit("Warning: thread_func: socket error reported on unix domain client socket (fd=%i) (id=%lld).\n", c->s, c->id);
					RemoveClientFromEPoll(c);
					break;
				}
				if (RearmEpoll(&ev) != 0) {
					logit("Error: thread_func: RearmEpoll() on unix domain client socket (fd=%i) (id=%lld).\n", c->s, c->id);
					ShutdownThreads();
					return (void*) EXIT_FAILURE;
				}
				break;
			case CLIENTYPE_PRECACHE:
				if (ev.events & EPOLLIN) {
					RecvPrecacheClient(c);
				}
//				if (ev.events & (~EPOLLIN)) {
//					logit("Warning: thread_func: socket error reported on unix domain client socket (fd=%i).\n", c->s);
//				}
				#ifdef DEBUG_LOG
					logit("DEBUG: thread_func: Precache client got it's one and only trigger, removing client (fd=%i).\n", c->s);
				#endif
				RemovePrecacheClient(c);
				continue; // continue while loop
//				break;
		}
		#ifdef DEBUG_LOG
			logit("DEBUG: thread_func: processing complete for events %08x for client (fd=%i) (type=%i) (id=%lld).\n", ev.events, c->s, c->type, c->id);
		#endif
		if (atomic_dec(c->refcount) == 0) {
			#ifdef DEBUG_LOG
				logit("DEBUG: thread_func: c->refcount hit zero, deleting and closing socket. (fd=%i) (type=%i) (id=%lld)\n", c->s, c->type, c->id);
			#endif
			close(c->s);
			free(c);
		}
	}
	#ifdef DEBUG_LOG
		logit("DEBUG: thread loop ended, returning 0.\n");
	#endif
	return 0;
}

int RearmEpoll(struct epoll_event *ev) {
	#ifdef DEBUG_LOG
		logit("DEBUG: RearmEpoll: called for client (fd=%i) (id=%lld).\n", ((struct client*) ev->data.ptr)->s, ((struct client*) ev->data.ptr)->id);
	#endif
	ev->events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLONESHOT;
	if (epoll_ctl(epfd, EPOLL_CTL_MOD, ((struct client*) ev->data.ptr)->s, ev) < 0) {
		logit("RearmEpoll: epoll_ctl(EPOLL_CTL_MOD) failed. errno=%i (%s)\n", errno, strerror(errno));
		return -1;
	}
	return 0;
}

// check for peer replies
// return: negative=error, zero=success, 1=rearmed epoll
int RecvUDP(int s, struct epoll_event *ev) {
	int rv;
	char buffer[9216];
	socklen_t sockaddr_len;
	struct sockaddr_in6 udpsockaddr;
	char ip_str[INET6_ADDRSTRLEN];

	while (1) {
		memset(&udpsockaddr, 0, sizeof(udpsockaddr));
		sockaddr_len = sizeof(udpsockaddr);
		if ((rv = recvfrom(s, buffer, sizeof(buffer), 0, &udpsockaddr, &sockaddr_len)) < 0) {
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				break;
			logit("Error: RecvUDP: recvfrom() errored. errno=%i (%s)\n", errno, strerror(errno));
			return -1;
		}
		if (ntohs(udpsockaddr.sin6_port) != config.UDPPort) {
			logit("Notice: RecvUDP: Remote source port != config.UDPPort. rv=%i. IP=%s, port=%i.\n", rv, inet_ntop(AF_INET6, &udpsockaddr.sin6_addr, ip_str, sizeof(ip_str)), ntohs(udpsockaddr.sin6_port));
			continue;
		}
		if (!CheckAllowedPeer(6, &udpsockaddr.sin6_addr.s6_addr)) {
			logit("Notice: RecvUDP: Remote source IP not an allowed peer. rv=%i. IP=%s, port=%i.\n", rv, inet_ntop(AF_INET6, &udpsockaddr.sin6_addr, ip_str, sizeof(ip_str)), ntohs(udpsockaddr.sin6_port));
			continue;
		}
		if (RearmEpoll(ev)) {
			logit("Error: RecvUDP: RearmEpoll failed for peer_sock.\n");
			return -1;
		}
		ProcessPeerPacket(&udpsockaddr, buffer, rv);
		return 1;
	}
	return 0;
}

// return: negative=error, zero=success, 1=rearmed epoll
int RecvClient(struct epoll_event *ev, struct client *c) {
	int rv;
	struct msghdr msg;
	struct iovec msgiov;
	char buffer[9216];
	char control[4096];
	#ifdef DEBUG_LOG
	struct ucred cred;
	int foundcred = 0;
	struct cmsghdr *cmsg;
	#endif

	msgiov.iov_base = buffer;
	msgiov.iov_len = sizeof(buffer);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &msgiov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	if ((rv = recvmsg(c->s, &msg, 0)) < 0) {
		if (errno == EWOULDBLOCK || errno == EAGAIN)
			return 0;
		if (errno == ECONNRESET) {
			logit("Notice: RecvClient: connection reset, dropping client. (id=%lld)\n", c->id);
			return -1;
		}
		logit("Warning: RecvClient: recvmsg() errored. errno=%i (%s) (id=%lld)\n", errno, strerror(errno), c->id);
		return -1;
	}
	if (rv == 0) {
		logit("Notice: RecvClient: no bytes received / connection reset, dropping client. (id=%lld)\n", c->id);
		return -1;
	}

	if (msg.msg_flags & MSG_TRUNC) {
		logit("Warning: RecvClient: recvdmsg() set [msg.msg_flags & MSG_TRUNC]. Client tried to send message too big for receive buffer, dropping client. (id=%lld)\n", c->id);
		return -1;
	}

	#ifdef DEBUG_LOG
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS) {
			memcpy(&cred, CMSG_DATA(cmsg), sizeof(cred));
			foundcred = 1;
		}
		else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
			// we don't want 'em, get rid of 'em
			dispose_fds((int *) CMSG_DATA(cmsg), (cmsg->cmsg_len - CMSG_LEN(0))/sizeof(int));
		}
	}
	if (!foundcred) {
		logit("Warning: RecvClient: no creds on message, dropping client. (id=%lld)\n", c->id);
		return -1;
	}
	#endif
	if (RearmEpoll(ev)) {
		logit("Warning: RecvClient: RearmEpoll failed, dropping client. (id=%lld)\n", c->id);
		return -1;
	}
	ProcessClientPacket(c, buffer, rv
	#ifdef DEBUG_LOG
	, &cred
	#endif
	);

	return 1;
}

void RecvPrecacheClient(struct client *c) {
	struct msghdr msg;
	struct iovec msgiov;
	char control[4096];
	struct ucred cred;
	int rv, foundcred = 0, far_fdno = -1;
	struct cmsghdr *cmsg;

	msgiov.iov_base = &far_fdno;
	msgiov.iov_len = sizeof(far_fdno);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &msgiov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	if ((rv = recvmsg(c->s, &msg, 0)) < 0) {
		if (errno == EWOULDBLOCK || errno == EAGAIN) {
			logit("Notice: RecvPrecacheClient: recvmsg would block, dropping client. (s=%i)\n", c->s);
			return;
		}
		if (errno == ECONNRESET) {
			logit("Notice: RecvPrecacheClient: connection reset, dropping client. (s=%i)\n", c->s);
			return;
		}
		logit("Warning: RecvPrecacheClient: recvmsg() errored. errno=%i (%s) (s=%i)\n", errno, strerror(errno), c->s);
		return;
	}

	if (rv == 0) {
		logit("Notice: RecvPrecacheClient: no bytes received / connection reset, dropping client. (s=%i)\n", c->s);
		return;
	}

	if (msg.msg_flags & MSG_TRUNC) {
		logit("Warning: RecvPrecacheClient: recvdmsg() set [msg.msg_flags & MSG_TRUNC]. Client tried to send message too big for receive buffer, dropping client. (s=%s)\n", c->s);
		return;
	}

	if (rv != sizeof(int)) {
		logit("Notice: RecvPrecacheClient: wrong number of bytes received, dropping client. (s=%i)\n", c->s);
		return;
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS && cmsg->cmsg_len >= (sizeof(struct cmsghdr) + sizeof(cred))) {
			memcpy(&cred, CMSG_DATA(cmsg), sizeof(cred));
			foundcred = 1;
		}
		else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
			// we don't want 'em, get rid of 'em
			dispose_fds((int *) CMSG_DATA(cmsg), (cmsg->cmsg_len - CMSG_LEN(0))/sizeof(int));
		}
	}
	if (!foundcred) {
		logit("Warning: RecvPrecacheClient: no creds on message, dropping client. (s=%i)\n", c->s);
		return;
	}
	if (cred.pid == 0) {
		logit("Warning: RecvPrecacheClient: pid == 0 on creds in message, dropping client. (s=%i)\n", c->s);
		return;
	}
	if (FindPIDFromSocketInode_addcache(cred.pid, far_fdno) != 0) {
		logit("Warning: RecvPrecacheClient: FindPIDFromSocketInode_addcache failed. (s=%i, pid=%i, fd=%i)\n", c->s, cred.pid, far_fdno);
		return;
	}
}

void ReleaseFoundClient(struct client **c) {
	if (atomic_dec((*c)->refcount) == 0) {
		#ifdef DEBUG_LOG
			logit("DEBUG: ReleaseFoundClient: c->refcount hit zero, deleting and closing socket. (fd=%i) (id=%lld)\n", (*c)->s, (*c)->id);
		#endif
		close((*c)->s);
		free(*c);
	}
	*c = NULL;
}

struct client * FindClientByID(uint64 clientID) {
	pthread_mutex_lock(&clientlist_mutex);
	for (struct client *c = clienthead; c; c = c ? c->next : NULL) {
		if (c->id == clientID) {
			atomic_inc(c->refcount);
			pthread_mutex_unlock(&clientlist_mutex);
			return c;
		}
	}
	pthread_mutex_unlock(&clientlist_mutex);
	return NULL;
}

// Used on both Unix and UDP sockets
int SendMsgToSock(int sock, struct sockaddr_in6 *sockaddr, char opcode, void* buffer1, int len1, void* buffer2, int len2) {
	int retval = -1;
	struct msghdr msg;
	struct iovec msgiov[3];

	msgiov[0].iov_base = &opcode;
	msgiov[0].iov_len = 1;
	msgiov[1].iov_base = (char*) buffer1;
	msgiov[1].iov_len = len1;
	msgiov[2].iov_base = (char*) buffer2;
	msgiov[2].iov_len = len2;

	memset(&msg, 0, sizeof(msg));
	if (sockaddr) {
		msg.msg_name = sockaddr;
		msg.msg_namelen = sizeof(struct sockaddr_in6);
	}
	msg.msg_iov = msgiov;
	msg.msg_iovlen = len2 ? 3 : (len1 ? 2 : 1);
	if (sendmsg(sock, &msg, 0) <= 0) {
		logit("Warning: SendMsgToSock: sendmsg failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	retval = 0;
cleanup:
	return retval;	
}

int Process_QueryLocalConnection(uint8 reply_opcode, const char* clientIDstring, char *buffer, int len, int sock, struct sockaddr_in6* sockaddr, uint32 max_nsgids) {
	struct query_sock* q = NULL;
	struct query_sock_response qr;
	uint32	inode;
	uid_t	uid;
	int count;
	gid_t gids[NGROUPS_MAX];
	pid_t pid = 0;

	if ((len - 1) != sizeof(struct query_sock)) {
		logit("Error: Process_QueryLocalConnection: size of data is not sizeof(struct peer_query), dropping client. (%s)\n", clientIDstring);
		return -1;
	}

	q = (struct query_sock *) &buffer[1];
	#ifdef DEBUG_LOG
		logit("DEBUG: Process_QueryLocalConnection: Got question, starting lookups... reply_opcode=%s (%i), queryID=0x%016llx (%s)\n",
			(reply_opcode == OP_QueryLocalConnectionResponse) ? "OP_QueryLocalConnectionResponse" : (reply_opcode == OP_QueryRemoteConnectionResponse) ? "OP_QueryRemoteConnectionResponse" : "unknown"
			, reply_opcode, q->queryid, clientIDstring);
	#endif
	if ((count = find_socket(q->ip_version, q->protocol, q->local_ip, q->local_port, q->remote_ip, q->remote_port, q->tcpstates, &inode, &uid
		, (q->flags & QS_Flag_PGIDInfo) || (q->flags & QS_Flag_ProcessInfo) || (q->flags & QS_Flag_SupGroups) ? &pid : NULL
		, q->flags & QS_Flag_DetailForRoot ? 1 : 0
		)) < 0) {
		logit("Error: Process_QueryLocalConnection: find_socket errored, dropping client. (%s)\n", clientIDstring);
		return -1;
	}
	memset(&qr, 0, sizeof(qr));
	qr.clientid = q->clientid;
	qr.queryid = q->queryid;
	
	if (count > 0) {
		qr.flags |= QS_Flag_HaveAnswer;
		qr.uid = uid;

		if ( ((q->flags & QS_Flag_PGIDInfo) || (q->flags & QS_Flag_ProcessInfo) || (q->flags & QS_Flag_SupGroups)) && (uid != 0 || (q->flags & QS_Flag_DetailForRoot)) ) {
			if (inode != 0 && pid > 0) {
				qr.pid = pid;
				if (GetProcessInfo(pid, &qr.uid, &qr.gid, q->flags & QS_Flag_SupGroups ? &qr.nsgids : NULL, q->flags & QS_Flag_SupGroups ? gids : NULL, q->flags & QS_Flag_SupGroups ? (max_nsgids < NGROUPS_MAX ? max_nsgids : NGROUPS_MAX) : 0) == 0) {
					qr.flags |= QS_Flag_PGIDInfo;
					qr.flags |= QS_Flag_ProcessInfo;
					if (q->flags & QS_Flag_SupGroups)
						qr.flags |= QS_Flag_SupGroups;
				}
#ifdef DEBUG_LOG
				else {
					logit("Notice: Process_QueryLocalConnection: Failed to get process info (pid=%i) (%s)\n", pid, clientIDstring);
				}
#endif
			}
#ifdef DEBUG_LOG
			else {
				logit("Notice: Process_QueryLocalConnection: Failed to find PID from INode# (inode=%i) (%s)\n", inode, clientIDstring);
			}
#endif
		}
	}

	#ifdef DEBUG_LOG
		logit("DEBUG: Process_QueryLocalConnection: Done, sending response. reply_opcode=%s (%i), queryID=0x%016llx, flags=%i (%s)\n",
			(reply_opcode == OP_QueryLocalConnectionResponse) ? "OP_QueryLocalConnectionResponse" : (reply_opcode == OP_QueryRemoteConnectionResponse) ? "OP_QueryRemoteConnectionResponse" : "unknown"
			, reply_opcode, qr.queryid, qr.flags, clientIDstring);
	#endif
	if (SendMsgToSock(sock, sockaddr, reply_opcode, &qr, sizeof(qr), gids, sizeof(gid_t) * qr.nsgids) != 0) {
		logit("Warning: Process_QueryLocalConnection: SendMsgToClient() failed. (%s)\n", clientIDstring);
		return -1;
	}
	return 0;
}

int GetIPv4(uint8 ip_version, void* IP, uint32* oIP4) {
	uint32 *IP6_parts = (uint32*) IP;
	if (ip_version == 4) {
		if (oIP4)
			*oIP4 = IP6_parts[0];
		return 1;
	}
	if (IP6_parts[0] == 0 && IP6_parts[1] == 0 && IP6_parts[2] == 0 && IP6_parts[3] == 0) {
		if (oIP4)
			*oIP4 = 0;
		return 1;
	}
	if (IP6_parts[0] == 0 && IP6_parts[1] == 0 && IP6_parts[2] == htonl(0xFFFF)) {
		if (oIP4)
			*oIP4 = IP6_parts[3];
		return 1;
	}
	if (IP6_parts[0] == 0 && IP6_parts[1] == 0 && IP6_parts[2] == 0 && IP6_parts[3] == htonl(1)) {
		if (oIP4)
			*oIP4 = htonl(0x7F000001);
		return 1;
	}
	return 0;
}

// 0 = nope, negative = error, 1 = allowed
int CheckAllowedPeer(uint8 ip_version, void* inIP) {
	uint32 IP4 = 0;
	void* IP = inIP;
	uint8 bytes, bits, bits_mask;
	#ifdef DEBUG_LOG
		char ip_str[INET6_ADDRSTRLEN];
	#endif

	#ifdef DEBUG_LOG
		logit("DEBUG: CheckAllowedPeer: IP=%s\n", inet_ntop(ip_version == 4 ? AF_INET : AF_INET6, IP, ip_str, sizeof(ip_str)));
	#endif
	if (IsLocalHost(ip_version, IP)) {
		#ifdef DEBUG_LOG
			logit("DEBUG: CheckAllowedPeer: Found localhost, returning 1.\n");
		#endif
		return 1;
	}
	if (GetIPv4(ip_version, inIP, &IP4)) {
		IP = &IP4;
		ip_version = 4;
		#ifdef DEBUG_LOG
			logit("DEBUG: CheckAllowedPeer: IPv4 (in IPv6)=%s\n", inet_ntop(AF_INET, IP, ip_str, sizeof(ip_str)));
		#endif
	}
	for (uint32 x=0; x<IDENT2D_CONFIG_MAX_IPRANGES; x++) {
		if (config.AllowedPeerIPRanges[x].mask == 0xFF)
			break;
		#ifdef DEBUG_LOG
			logit("DEBUG: CheckAllowedPeer: x=%i, ip=%s, mask=%i\n", x, inet_ntop(config.AllowedPeerIPRanges[x].ip_version == 4 ? AF_INET : AF_INET6, config.AllowedPeerIPRanges[x].ip, ip_str, sizeof(ip_str)), config.AllowedPeerIPRanges[x].mask);
		#endif
		if (config.AllowedPeerIPRanges[x].ip_version != ip_version)
			continue;
		bytes = config.AllowedPeerIPRanges[x].mask / 8;
		bits = config.AllowedPeerIPRanges[x].mask % 8;
		bits_mask = 0xFF << (8 - bits);
		if (memcmp(config.AllowedPeerIPRanges[x].ip, IP, bytes) == 0 && (bits == 0 || (config.AllowedPeerIPRanges[x].ip[bytes] & bits_mask) == (((uint8*) IP)[bytes] & bits_mask))) {
			#ifdef DEBUG_LOG
				logit("DEBUG: CheckAllowedPeer: Found match, returning 1.\n");
			#endif
			return 1;
		}
	}
	#ifdef DEBUG_LOG
		logit("DEBUG: CheckAllowedPeer: no match, returning 0\n");
	#endif
	return 0;
}


void ProcessClientPacket(struct client *c, char *buffer, int len
	#ifdef DEBUG_LOG
	, struct ucred *cred
	#endif
	) {
	char	clientIDstring[256];
	#ifdef DEBUG_LOG
		char ip_str[INET6_ADDRSTRLEN];
	#endif

	#ifdef DEBUG_LOG
		sprintf(clientIDstring, "#%lld, pid=%i, uid=%i, gid=%i", c->id, cred->pid, cred->uid, cred->gid);
	#else
		sprintf(clientIDstring, "#%lld", c->id);
	#endif

	switch (buffer[0]) {
		case OP_Hello: {
			logit("Notice: Hello received (%s): %.*s\n", clientIDstring, len, &buffer[1]);
			break;
		}
		case OP_QueryLocalConnection: {
			#ifdef DEBUG_LOG
				logit("DEBUG: QueryLocalConnection received (%s)\n", clientIDstring);
			#endif

			if (Process_QueryLocalConnection(OP_QueryLocalConnectionResponse, clientIDstring, buffer, len, c->s, NULL, 0xFFFFFFFF) != 0) {
				logit("Warning: ProcessClientPacket(OP_QueryLocalConnection): Process_QueryLocalConnection() failed, dropping client. (%s)\n", clientIDstring);
				removeclient(c);
				return;
			}

			break;
		}
		case OP_QueryRemoteConnection: {
			struct query_sock* q = NULL;
			struct sockaddr_in6 udpsockaddr;
			int rv;

			#ifdef DEBUG_LOG
				logit("DEBUG: QueryRemoteConnection received (%s)\n", clientIDstring);
			#endif

			if ((len - 1) != sizeof(struct query_sock)) {
				logit("Warning: ProcessClientPacket(OP_QueryRemoteConnection): size of data is not sizeof(struct peer_query), dropping client. (%s)\n", clientIDstring);
				removeclient(c);
				return;
			}

			q = (struct query_sock *) &buffer[1];
// short-circut process localhost
			if (IsLocalHost(q->ip_version, q->local_ip)) {
				#ifdef DEBUG_LOG
					logit("DEBUG: ProcessClientPacket: Bypass processing localhost remote request: clientID=(%s), queryID=0x%016llx\n", clientIDstring, q->queryid);
				#endif
				if (Process_QueryLocalConnection(OP_QueryRemoteConnectionResponse, clientIDstring, buffer, len, c->s, NULL, 0xFFFFFFFF) != 0) {
					logit("Warning: ProcessiClientPacket(remote-localhost): Process_QueryLocalConnection() failed, dropping client. (%s)\n", clientIDstring);
					removeclient(c);
					return;
				}
				break;
			}
			if (CheckAllowedPeer(q->ip_version, q->local_ip) != 1) {
				struct query_sock_response qr;

				logit("Notice: ProcessClientPacket(OP_QueryRemoteConnection): proposed peer not in AllowedPeerIPs, rejecting question. (%s)\n", clientIDstring);

				memset(&qr, 0, sizeof(qr));
				qr.clientid = c->id;
				qr.queryid = q->queryid;
				//qr.flags = 0 means no QS_Flag_HaveAnswer
				if (SendMsgToSock(c->s, NULL, OP_QueryRemoteConnectionResponse, &qr, sizeof(qr), NULL, 0) != 0) {
					logit("Warning: ProcessClientPacket(OP_QueryRemoteConnection): SendMsgToClient() failed, dropping client. (%s)\n", clientIDstring);
					removeclient(c);
					return;
				}
				return;
			}

			q->clientid = c->id;

			memset(&udpsockaddr, 0, sizeof(udpsockaddr));
			udpsockaddr.sin6_family = AF_INET6;
			udpsockaddr.sin6_port = htons(config.UDPPort);
			if (q->ip_version == 6)
				memcpy(&udpsockaddr.sin6_addr, q->local_ip, 16);
			else {
				*((uint16*) &udpsockaddr.sin6_addr.s6_addr[10]) = 0xFFFF;
				*((uint32*) &udpsockaddr.sin6_addr.s6_addr[12]) = *((uint32*) &q->local_ip);
			}
			#ifdef DEBUG_LOG
				logit("DEBUG: ProcessClientPacket(OP_QueryRemoteConnection): Sending reply to IPv%i address %s.\n", q->ip_version, inet_ntop(q->ip_version == 4 ? AF_INET : AF_INET6, q->local_ip, ip_str, sizeof(ip_str)));
			#endif

			if ((rv = sendto(peer_sock, buffer, len, 0, &udpsockaddr, sizeof(udpsockaddr))) != len) {
				if (rv < 0)
					logit("Warning: ProcessClientPacket(OP_QueryRemoteConnection): sendto() failed, dropping client. rv=%i, errno=%i (%s). (%s)\n", rv, errno, strerror(errno), clientIDstring);
				else
					logit("Warning: ProcessClientPacket(OP_QueryRemoteConnection): sendto() failed, didn't send all data, dropping client. rv=%i. (%s)\n", rv, clientIDstring);
				removeclient(c);
				return;
			}
			#ifdef DEBUG_LOG
				logit("DEBUG: QueryRemoteConnection sent to peer (queryID=0x%016llx, %s)\n", q->queryid, clientIDstring);
			#endif
			break;
		}
		default: {
			logit("Warning: ProcessClientPacket: Unknown opcode received, dropping client. OPCode=%i, %s\n", buffer[0], clientIDstring);
			removeclient(c);
			return;
		}
	}
}

void ProcessPeerPacket(struct sockaddr_in6* sockaddr, char *buffer, int len) {
	char clientIDstring[256];
	int r;
	char ip_str[INET6_ADDRSTRLEN];

	switch (buffer[0]) {
		case OP_Hello: {
			logit("Notice: Hello received (IP=%s)\n", inet_ntop(AF_INET6, &sockaddr->sin6_addr, ip_str, sizeof(ip_str)));
			break;
		}
		case OP_QueryRemoteConnection: {
			struct query_sock* q = NULL;

			#ifdef DEBUG_LOG
				logit("DEBUG: QueryRemoteConnection received (IP=%s)\n", inet_ntop(AF_INET6, &sockaddr->sin6_addr, ip_str, sizeof(ip_str)));
			#endif

			if (len != (sizeof(struct query_sock) + 1)) {
				logit("Warning: ProcessPeerPacket: data size from peer_sock is not sizeof(struct peer_query) + 1. len=%i. IP=%s\n", len, inet_ntop(AF_INET6, &sockaddr->sin6_addr, ip_str, sizeof(ip_str)));
				return;
			}

			q = (struct query_sock *) &buffer[1];
			#ifdef DEBUG_LOG
				logit("DEBUG: ProcessPeerPacket: clientID=%lld, queryID=0x%016llx, IP=%s\n", q->clientid, q->queryid, inet_ntop(AF_INET6, &sockaddr->sin6_addr, ip_str, sizeof(ip_str)));
			#endif
			sprintf(clientIDstring, "%s#%lld", inet_ntop(AF_INET6, &sockaddr->sin6_addr, ip_str, sizeof(ip_str)), q->clientid);
			if (Process_QueryLocalConnection(OP_QueryRemoteConnectionResponse, clientIDstring, buffer, len, peer_sock, sockaddr, 0xFFFFFFFF) != 0) {
				logit("Warning: ProcessPeerPacket: Process_QueryLocalConnection() failed, no reply will be sent. (%s)\n", clientIDstring);
				return;
			}
			break;
		}
		case OP_QueryRemoteConnectionResponse: {
			struct query_sock_response* qr = NULL;
			struct client * c = NULL;

			#ifdef DEBUG_LOG
				logit("DEBUG: OP_QueryRemoteConnectionResponse received (IP=%s)\n", inet_ntop(AF_INET6, &sockaddr->sin6_addr, ip_str, sizeof(ip_str)));
			#endif

			if (len < (sizeof(struct query_sock_response) + 1)) {
				logit("Warning: ProcessPeerPacket: data size from peer_sock is not >= sizeof(struct query_sock_response) + 1. len=%i. IP=%s\n", len, inet_ntop(AF_INET6, &sockaddr->sin6_addr, ip_str, sizeof(ip_str)));
				return;
			}

			qr = (struct query_sock_response *) &buffer[1];
			#ifdef DEBUG_LOG
				logit("DEBUG: ProcessPeerPacket: clientID=%lld, queryID=0x%016llx, IP=%s\n", qr->clientid, qr->queryid, inet_ntop(AF_INET6, &sockaddr->sin6_addr, ip_str, sizeof(ip_str)));
			#endif
			
			if ((c = FindClientByID(qr->clientid)) == NULL) {
				logit("Warning: ProcessPeerPacket: could not find client with ID=%lld to match packet from IP=%s\n", qr->clientid, inet_ntop(AF_INET6, &sockaddr->sin6_addr, ip_str, sizeof(ip_str)));
				return;
			}
			// we now hold a refcount on cient

			r = SendMsgToClient(c, OP_QueryRemoteConnectionResponse, &buffer[1], len-1);
			ReleaseFoundClient(&c);
			if (r != 0) {
				logit("Warning: ProcessPeerPacket: SendMsgToClient() failed. (clientID=%lld, queryID=0x%016llx, IP=%s)\n", qr->clientid, qr->queryid, inet_ntop(AF_INET6, &sockaddr->sin6_addr, ip_str, sizeof(ip_str)));
				return;
			}
			#ifdef DEBUG_LOG
				logit("DEBUG: ProcessPeerPacket: response from peer sent to client. clientID=%lld, queryID=0x%016llx, flags=%u, IP=%s\n", qr->clientid, qr->queryid, qr->flags, inet_ntop(AF_INET6, &sockaddr->sin6_addr, ip_str, sizeof(ip_str)));
			#endif
			break;
		}
		default: {
			logit("Warning: ProcessPeerPacket: Unknown opcode received, no reply will be sent. OPCode=%i, IP=%s\n", buffer[0], inet_ntop(AF_INET6, &sockaddr->sin6_addr, ip_str, sizeof(ip_str)));
			return;
		}
	}
}

// Queries /proc/ for info about the process. Any of the pointers can be null to skip that info.
// nsgrps: outbound = how many sgrps the process had. If is null, sgrps is ignored and SHOULD be null
// sgids_size: size of sgrps buffer (in # gid_t entries), SHOULD be zero if sgids is null
int GetProcessInfo(pid_t pid, uid_t* euid, gid_t* egid, uint32* nsgids, gid_t* sgids, uint32 sgids_size) {
	int retval = -1;
	char buf[262144];
	FILE* f = NULL;
	uint32 junk;
	uint8 euid_ok = 0, egid_ok = 0, sgids_ok = 0;

	#ifdef DEBUG_LOG
		logit("DEBUG: GetProcessInfo: called: pid=%i, euid=%p, egid=%p, nsgids=%p, sgids=%p, sgids_size=%i\n", pid, euid, egid, nsgids, sgids, sgids_size);
	#endif
	
	if (euid == NULL)
		euid_ok = 1;
	if (egid == NULL)
		egid_ok = 1;
	if (nsgids == NULL && sgids == NULL)
		sgids_ok = 1;

	sprintf(buf, "/proc/%d/status", pid);
	if ((f = fopen(buf, "r")) == NULL) {
		logit("Warning: GetProcessInfo: fopen failed for pid %i. errno=%i (%s)\n", pid, errno, strerror(errno));
		goto cleanup;
	}
	while (fgets(buf, sizeof(buf), f)) {
		if (euid_ok == 0 && strncmp(buf, "Uid:", 4) == 0) {
			if (sscanf(&buf[5], "%*u %u %u", euid, &junk) != 2) {
				logit("Warning: GetProcessInfo: sscanf(uid) failed for pid %i. errno=%i (%s)\n", pid, errno, strerror(errno));
				goto cleanup;
			}
			euid_ok = 1;
		}
		else if (egid_ok == 0 && strncmp(buf, "Gid:", 4) == 0) {
			if (sscanf(&buf[5], "%*u %u %u", egid, &junk) != 2) {
				logit("Warning: GetProcessInfo: sscanf(gid) failed for pid %i. errno=%i (%s)\n", pid, errno, strerror(errno));
				goto cleanup;
			}
			egid_ok = 1;
		}
		else if (sgids_ok == 0 && strncmp(buf, "Groups:", 7) == 0) {
			int x = 7, rv, consumed;
			uint32 found_gids = 0;
			size_t sl;
			
			sl = strlen(buf);
			#ifdef DEBUG_LOG
				logit("DEBUG: GetProcessInfo: sl=%i, line='%s'\n", sl, buf);
			#endif
			// 123456789
			// Groups: \n
			if (sl > 9) {
				while (1) {
					rv = sscanf(&buf[x], " %u %n", &junk, &consumed);
					if (rv < 0) {
						logit("Warning: GetProcessInfo: sscanf(sgids) failed for pid %i. errno=%i (%s)\n", pid, errno, strerror(errno));
						goto cleanup;
					}
					if (!(rv == 1 || rv == 2)) // spec is unclear on whether %n is counted in return value
						break;
					found_gids++;
					if (sgids && found_gids <= sgids_size)
						sgids[found_gids - 1] = junk;
					x += consumed;
					if (x >= sl)
						break;
				}
			}
			if (nsgids)
				*nsgids = found_gids;
			sgids_ok = 1;
		}
		if (euid_ok && egid_ok && sgids_ok) {
			retval = 0;
			break;
		}
	}
	#ifdef DEBUG_LOG
		logit("DEBUG: GetProcessInfo: done. retval=%i\n", retval);
	#endif
	
cleanup:
	if (f)
		fclose(f);
	f = NULL;

	return retval;
}
