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
#include "apr_strings.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_log.h"
#include "apr_optional.h"
#include "mod_rewrite.h"

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

typedef u_int8_t uint8;
typedef u_int16_t uint16;
typedef u_int32_t uint32;
typedef u_int64_t uint64;

#include "ident2d_api.h"
#include "tcp_states.h"

#define IDENT2_LOCAL 1
#define IDENT2_REMOTE 2

#define ERRTAG "Mod_Rewrite_FWfunc "
#define DEFAULT_CACHE_TIMEOUT	1500	// 1.5s

module AP_MODULE_DECLARE_DATA rewrite_fwfunc_module;

typedef struct {
// state
	apr_pool_t		*pool;
#if APR_HAS_THREADS
	apr_thread_mutex_t	*mutex;
#endif
	apr_hash_t		*cache_fn;
	apr_hash_t		*cache_db;
	apr_hash_t		*cache_fh;

	int				ident2_sock;
	uint64			ident2_queryID;
} rewrite_fwfunc_svr_config_rec;

typedef struct {
// config
	int			cache_timeout;
	int			ident2_timeout; // in ms
	int			ident2_tries; // 1-x (config setting of 0|1 === 1 try)
} rewrite_fwfunc_dir_config_rec;

static void rewrite_fwfunc_child_init(apr_pool_t* pchild, server_rec *s) {
	apr_status_t rv;

	rewrite_fwfunc_svr_config_rec* sconf = ap_get_module_config(s->module_config, &rewrite_fwfunc_module);

	rv = apr_pool_create(&sconf->pool, pchild);
	if (rv != APR_SUCCESS) {
		ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, pchild, "Failed to create subpool for rewrite_fwfunc_module");
		return;
	}

#if APR_HAS_THREADS
	rv = apr_thread_mutex_create(&sconf->mutex, APR_THREAD_MUTEX_DEFAULT, pchild);
	if (rv != APR_SUCCESS) {
		ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, pchild, "Failed to create mutex for rewrite_fwfunc_module");
		return;
	}
#endif

	sconf->cache_fn = apr_hash_make(sconf->pool);
	sconf->cache_db = apr_hash_make(sconf->pool);
	sconf->cache_fh = apr_hash_make(sconf->pool);
	
	sconf->ident2_sock = -1;
	sconf->ident2_queryID = 0;
}

static void* create_server_config(apr_pool_t *p, server_rec* s) {
	rewrite_fwfunc_svr_config_rec *conf = apr_palloc(p, sizeof(*conf));

	return conf;
}

static void* create_dir_config(apr_pool_t *p, char *d) {
	rewrite_fwfunc_dir_config_rec *conf = apr_palloc(p, sizeof(*conf));

	conf->cache_timeout = DEFAULT_CACHE_TIMEOUT;
	conf->ident2_timeout = 0;
	conf->ident2_tries = 0;

	return conf;
}

static void* merge_dir_config(apr_pool_t* p, void* in_base, void* in_add) {
	rewrite_fwfunc_dir_config_rec *base = (rewrite_fwfunc_dir_config_rec*) in_base;
	rewrite_fwfunc_dir_config_rec *add = (rewrite_fwfunc_dir_config_rec*) in_add;
	rewrite_fwfunc_dir_config_rec *conf = apr_palloc(p, sizeof(*conf));

	conf->cache_timeout = add->cache_timeout != -1 ? add->cache_timeout : base->cache_timeout;
	conf->ident2_timeout = add->ident2_timeout != -1 ? add->ident2_timeout : base->ident2_timeout;
	conf->ident2_tries = add->ident2_tries != -1 ? add->ident2_tries : base->ident2_tries;

	return conf;
}

int ConnectIdent2Sock(request_rec *r, int *ident2_sock) {
	// try connection to ident2d
	struct sockaddr_un addr;

	if ((*ident2_sock = socket(PF_UNIX, SOCK_SEQPACKET, 0)) < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "socket() for ident2_sock failed. errno=%i (%s)", errno, strerror(errno));
		*ident2_sock = -1;
		return 0;
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, IDENT2_SOCKNAME, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path)-1] = '\0';

	if (connect(*ident2_sock, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "connect(ident2_sock) failed. errno=%i (%s)", errno, strerror(errno));
		close(*ident2_sock);
		*ident2_sock = -1;
		return 0;
	}

	// set nonblocking on our ident2d socket
	if (fcntl(*ident2_sock, F_SETFL, O_NONBLOCK | O_ASYNC) < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "fcntl(ident2_sock, O_NONBLOCK | O_ASYNC) failed. errno=%i (%s)", errno, strerror(errno));
		return -1;
	}

	return 1;
}

struct query_sock_response * SyncAskIdent2(request_rec *r, uint8 LocalOrRemote, uint8 flags, uint8 ip_version, uint8 protocol, void* lIP, uint16 lPort, void* rIP, uint16 rPort, uint32 tcp_states) {
	rewrite_fwfunc_svr_config_rec *sconf = ap_get_module_config(r->server->module_config, &MODULE_NAME_module);
	rewrite_fwfunc_dir_config_rec *dconf = ap_get_module_config(r->per_dir_config, &MODULE_NAME_module);
	static __thread uint8 buffer[16384];
	struct msghdr msg_s, msg_r;
	struct iovec iov_s[2], iov_r[2];
	char opcode_s, opcode_r;
	struct query_sock qs;
	int rv;
	struct timespec orig, now, select_timeout, elapsed;
	char ip_str[INET6_ADDRSTRLEN];
	int num_tried = 0;
	fd_set readfds;
	time_t timeout_sec = 0;
	long timeout_nsec = 500000000; // 500ms

	if (dconf->ident2_timeout != 0) {
		timeout_sec = dconf->ident2_timeout / 1000;
		timeout_nsec = (dconf->ident2_timeout % 1000) * 1000000;
	}
	ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r, "Timeout set to %lu seconds and %lu nanoseconds, dconf->ident2_timeout=%i", timeout_sec, timeout_nsec, dconf->ident2_timeout);

	if (sconf->ident2_sock == -1) {
		if (ConnectIdent2Sock(r, &sconf->ident2_sock) != 1) {
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
	qs.queryid = ++sconf->ident2_queryID;
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

	ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "Sending ident2d question:");
	ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "opcode: %s", opcode_s == OP_QueryLocalConnection ? "OP_QueryLocalConnection" : "OP_QueryRemoteConnection");
	ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "queryid: 0x%016lx", qs.queryid);
	ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "flags: %i", qs.flags);
	ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "ip_version: %i", qs.ip_version);
	ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "protocol: %i", qs.protocol);
	ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "tcpstates: %i (0x%08x)", qs.tcpstates, qs.tcpstates);
	ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "local_ip: %s", inet_ntop(ip_version == 4 ? AF_INET : AF_INET6, qs.local_ip, ip_str, sizeof(ip_str)));
	ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "local_port: %i", qs.local_port);
	ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "remote_ip: %s", inet_ntop(ip_version == 4 ? AF_INET : AF_INET6, qs.remote_ip, ip_str, sizeof(ip_str)));
	ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "remote_port: %i", qs.remote_port);
	ap_log_rdata(APLOG_MARK, APLOG_TRACE8, r, "struct query_sock:", &qs, sizeof(qs), AP_LOG_DATA_SHOW_OFFSET);
	ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "---------------------------");

	iov_s[0].iov_base = &opcode_s;
	iov_s[0].iov_len = 1;
	iov_s[1].iov_base = &qs;
	iov_s[1].iov_len = sizeof(qs);

	memset(&msg_s, 0, sizeof(msg_s));
	msg_s.msg_iov = iov_s;
	msg_s.msg_iovlen = 2;

	if (sendmsg(sconf->ident2_sock, &msg_s, 0) == -1) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "sendmsg(ident2_sock) failed, closing socket. errno=%i (%s)", errno, strerror(errno));
		close(sconf->ident2_sock);
		sconf->ident2_sock = -1;
		errno = ECOMM;
		return NULL;
	}

	clock_gettime(CLOCK_MONOTONIC, &orig);
	select_timeout.tv_sec = timeout_sec;
	select_timeout.tv_nsec = timeout_nsec;
	while (1) {
		if (select_timeout.tv_sec == 0 && select_timeout.tv_nsec == 0) // signal from wrong queryID loop that it had no time remaining on current retry
			rv = 0;
		else {
			FD_ZERO(&readfds);
			FD_SET(sconf->ident2_sock, &readfds);
			rv = pselect(sconf->ident2_sock + 1, &readfds, NULL, NULL, &select_timeout, NULL);
		}
		if (rv == 0) {
			// 0 == we timed out
			num_tried++;
			if (num_tried >= dconf->ident2_tries) {
				ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "Out of retries, returning timeout. num_tried(%i) >= dconf->ident2_tries(%i)", num_tried, dconf->ident2_tries);
				errno = ETIMEDOUT;
				return NULL;
			}
			if (sendmsg(sconf->ident2_sock, &msg_s, 0) == -1) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "sendmsg(ident2_sock) failed, closing socket. errno=%i (%s)", errno, strerror(errno));
				close(sconf->ident2_sock);
				sconf->ident2_sock = -1;
				errno = ECOMM;
				return NULL;
			}
			clock_gettime(CLOCK_MONOTONIC, &orig);
			select_timeout.tv_sec = timeout_sec;
			select_timeout.tv_nsec = timeout_nsec;
			continue;
		}
		if (rv < 0) {
			// some error... other signal maybe, or something worse, bail
			ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r, "pselect returned %i. Bailing. errno=%i (%s)", rv, errno, strerror(errno));
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
	
		rv = recvmsg(sconf->ident2_sock, &msg_r, 0);
		if (rv <= 0) {
			if (rv == 0 || errno == ECONNRESET) {
				ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "Lost connection to ident2d");
				close(sconf->ident2_sock);
				sconf->ident2_sock = -1;
				errno = ECONNRESET;
				return NULL;
			}
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "recvmsg(ident2_sock) errored. errno=%i (%s)", errno, strerror(errno));
			return NULL;
		}
		else if ( rv < (sizeof(struct query_sock_response) + sizeof(opcode_r)) ) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "recvmsg(ident2_sock) returned message too short to be useful. Dropping ident2d connection. rv=%i", rv);
			close(sconf->ident2_sock);
			sconf->ident2_sock = -1;
			errno = ENODATA;
			return NULL;
		}
		else if (opcode_r != OP_QueryRemoteConnectionResponse) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "recvmsg(ident2_sock) returned unexpected opcode. Dropping ident2d connection. opcode=%i", opcode_r);
			close(sconf->ident2_sock);
			sconf->ident2_sock = -1;
			errno = EPROTO;
			return NULL;
		}

		// got actionable message
		struct query_sock_response *qsr = (struct query_sock_response *) &buffer[0];

		ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "Got ident2d response: %s", opcode_r == OP_QueryLocalConnectionResponse ? "OP_QueryLocalConnectionResponse" : "OP_QueryRemoteConnectionResponse");
		ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "queryid: 0x%016lx", qsr->queryid);
		ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "flags: %i", qsr->flags);
		ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "pid: %i", qsr->pid);
		ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "uid: %i", qsr->uid);
		ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "gid: %i", qsr->gid);
		ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "nsgids: %i", qsr->nsgids);
		for (int x=0; x<qsr->nsgids; x++)
			ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "sgids[%i]: %i", x, qsr->sgids[x]);
		ap_log_rdata(APLOG_MARK, APLOG_TRACE8, r, "struct query_sock_response:", qsr, sizeof(struct query_sock_response), AP_LOG_DATA_SHOW_OFFSET);
		ap_log_rerror(APLOG_MARK, APLOG_TRACE7, 0, r, "---------------------------");

		if (qsr->queryid != qs.queryid) {
			// wrong packet (late reply from an earlier question), skip... but only wait the remainder of our time
			ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Got stale reply (got: 0x%016lx, expected: 0x%016lx)", qsr->queryid, qs.queryid);
			clock_gettime(CLOCK_MONOTONIC, &now);
			elapsed.tv_sec = now.tv_sec - orig.tv_sec;
			if (now.tv_nsec < orig.tv_nsec) {
				elapsed.tv_sec--;
				elapsed.tv_nsec = 1000000000 + (now.tv_nsec - orig.tv_nsec);
			}
			else
				elapsed.tv_nsec = now.tv_nsec - orig.tv_nsec;

			if (elapsed.tv_sec > timeout_sec || (elapsed.tv_sec == timeout_sec && elapsed.tv_nsec >= timeout_nsec)) {
				select_timeout.tv_sec = 0;
				select_timeout.tv_nsec = 0;
				continue;
			}

			select_timeout.tv_sec = timeout_sec - elapsed.tv_sec;
			if (elapsed.tv_nsec > timeout_nsec) {
				select_timeout.tv_sec--;
				select_timeout.tv_nsec = 1000000000 - (elapsed.tv_nsec - timeout_nsec);
			}
			else
				select_timeout.tv_nsec = timeout_nsec - elapsed.tv_nsec;

			continue;
		}
			
		return qsr;
	} // while
	return NULL;
}

/*static char * rewrite_fwfunc_fn(request_rec *r, char* key) {
	rewrite_fwfunc_svr_config_rec *sconf = ap_get_module_config(r->per_dir_config, &MODULE_NAME_module);

	return NULL;
}

static char * rewrite_fwfunc_db(request_rec *r, char* key) {
	rewrite_fwfunc_svr_config_rec *sconf = ap_get_module_config(r->per_dir_config, &MODULE_NAME_module);

	return NULL;
}*/

int hpIsConnectionOK(request_rec *r, struct query_sock_response *qsr, struct passwd *pwd, gid_t* supgroups, int nsupgroups) {
	if (!(qsr->flags & QS_Flag_HaveAnswer)) {
		ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "No answer in ident2 response.");
		return 0;
	}
	if (qsr->uid == pwd->pw_uid)
		return 1;
	if (!(qsr->flags & QS_Flag_PGIDInfo)) {
		ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "No primary GID in ident2 response.");
		return 0;
	}
	if (qsr->gid == pwd->pw_gid)
		return 1;
	for (int x=0; x<nsupgroups; x++) {
		if (qsr->gid == supgroups[x])
			return 1;
	}
	return 0;
}

char * rewrite_fwfunc_fh(request_rec *r, char *key) {
//	rewrite_fwfunc_svr_config_rec *sconf = ap_get_module_config(r->per_dir_config, &MODULE_NAME_module);

	char *wsdst = NULL, *wsdst_host = NULL, *wsdst_port = NULL;
	struct hostent *he = NULL;
	struct in_addr *in = NULL;
	char *errcheck;
	long long_port;
	uint16 port;
	struct query_sock_response *qsr = NULL;
	struct passwd *pwd = NULL;
	gid_t supgroups[NGROUPS_MAX];
	int nsupgroups;

	// dup the key so we can modify the buffer without side effects
	wsdst = apr_pstrdup(r->pool, key);

	if ((wsdst_port = strrchr(wsdst, ':')) == NULL) {
		if ((wsdst_port = strrchr(wsdst, '-')) == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "strrchr(wsdst_port) failed.");
			return NULL;
		}
	}
	*wsdst_port = '\0';
	wsdst_port++;
	wsdst_host = wsdst;

	// get user info
	if ((pwd = getpwnam(r->user)) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "getpwnam(r->user) failed.");
		return NULL;
	}
	nsupgroups = NGROUPS_MAX;
	if (getgrouplist(r->user, pwd->pw_gid, supgroups, &nsupgroups) < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "getgrouplist(r->user=%s) failed. errno=%i (%s)", r->user, errno, strerror(errno));
		return NULL;
	}

	// lookup IP address of target
	if ((he = gethostbyname2(wsdst_host, AF_INET)) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "gethostbyname2(wsdst_host) failed. errno=%i (%s)", errno, strerror(errno));
		return NULL;
	}
	if (he->h_length == 0) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "gethostbyname2(wsdst_host) returned no entries.");
		return NULL;
	}
	if ((in = (struct in_addr *) he->h_addr_list[0]) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "gethostbyname2(wsdst_host) returned no data.");
		return NULL;
	}

	// parse port number
	long_port = strtol(wsdst_port, &errcheck, 10);
	if (errcheck == NULL || (errcheck[0] != '\0' && errcheck[0] != '\n')) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "Failed to parse port number, strtol had leftover data.");
		return NULL;
	}
	if (long_port < 0 || long_port > 0xFFFF) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "Failed to parse port number, strtol return out of range for a uint16.");
		return NULL;
	}
	port = (uint16) long_port;

	ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r, "IP=%s, port=%i", inet_ntoa(*in), port);

	// Ask ident2 who owns the far port
	//QS_Flag_ProcessInfo | QS_Flag_SupGroups
	if ((qsr = SyncAskIdent2(r, IDENT2_REMOTE, QS_Flag_PGIDInfo, 4, IPPROTO_TCP, &in->s_addr, port, NULL, 0, TCPF_LISTEN)) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "SyncAskIdent2 returned NULL. errno=%i (%s)", errno, strerror(errno));
		return NULL;
	}

	// make a decision
	if (hpIsConnectionOK(r, qsr, pwd, supgroups, nsupgroups))
		return apr_psprintf(r->pool,  "%s:%hu", inet_ntoa(*in), port);
	else
		return NULL;
}

#define WHERE_ALLOWED ACCESS_CONF

/* Module data */
static const command_rec rewrite_fwfunc_commands[] = {
	AP_INIT_TAKE1("RewriteFWfunc_cache_timeout", ap_set_int_slot, (void *)APR_OFFSETOF(rewrite_fwfunc_dir_config_rec, cache_timeout), WHERE_ALLOWED, "How long to cache successful requests (in ms)"),
	AP_INIT_TAKE1("RewriteFWfunc_ident2_timeout", ap_set_int_slot, (void *)APR_OFFSETOF(rewrite_fwfunc_dir_config_rec, ident2_timeout), WHERE_ALLOWED, "How long to wait for each ident2 reply (in ms)"),
	AP_INIT_TAKE1("RewriteFWfunc_ident2_tries", ap_set_int_slot, (void *)APR_OFFSETOF(rewrite_fwfunc_dir_config_rec, ident2_tries), WHERE_ALLOWED, "How many ident2 queries to send before giving up"),

  { NULL }
};

/* register hooks at the apache server */
static void rewrite_fwfunc_register_hooks(apr_pool_t *p) {
	APR_OPTIONAL_FN_TYPE(ap_register_rewrite_mapfunc) *register_rewrite_mapfunc = APR_RETRIEVE_OPTIONAL_FN(ap_register_rewrite_mapfunc);

	ap_hook_child_init(rewrite_fwfunc_child_init, NULL, NULL, APR_HOOK_MIDDLE);
//	ap_register_rewrite_mapfunc("fw_fn", &rewrite_fwfunc_fn);
//	ap_register_rewrite_mapfunc("fw_db", &rewrite_fwfunc_db);
	register_rewrite_mapfunc("fw_fh", &rewrite_fwfunc_fh);
}

AP_DECLARE_MODULE(rewrite_fwfunc) = {
	STANDARD20_MODULE_STUFF,
	create_dir_config,			/* per-directory config creater */
	merge_dir_config,			/* dir merger --- default is to override */
	create_server_config,					/* server config creator */
	NULL,					/* server config merger */
	rewrite_fwfunc_commands,		/* command table */
	rewrite_fwfunc_register_hooks		/* set up other request processing hooks */
};
