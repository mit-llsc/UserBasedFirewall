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
#include <sys/types.h>
#define IDENT2_SOCKNAME			"/var/run/ident2d.sock"
#define IDENT2PRECACHE_SOCKNAME	"/var/run/ident2d_cache.sock"

// There is lossiness in the underlying protocols. So assume a question could go unanswered.
#define OP_Hello 0
#define OP_QueryLocalConnection 1
#define OP_QueryLocalConnectionResponse 2
#define OP_QueryRemoteConnection 3
#define OP_QueryRemoteConnectionResponse 4

#define QS_Flag_HaveAnswer		(1<<0) // have an answer, UID field is valid (from socket info)
#define QS_Flag_PGIDInfo		(1<<1) // want/have primary GID info (from socket info or process info)
#define QS_Flag_ProcessInfo		(1<<2) // want/have process info (pid, uid, gid - uid/gid from socket info is overwritten)
#define QS_Flag_SupGroups		(1<<3) // want/have supplimental groups
#define QS_Flag_DetailForRoot	(1<<4) // QS_Flag_ProcessInfo, QS_Flag_PGIDInfo and QS_Flag_SupGroups are ignored for root unless this is set

#define QS_Max_Remote_SupGroups		350		// 1400 bytes

#pragma pack(1)
struct query_sock {
	uint64	clientid;		// used by netidd for peer comm, client should set to zero
	uint64	queryid;		// available for client use
	uint8	flags;
	uint8	ip_version;
	uint8	protocol;
	uint32	tcpstates;		// TCP Flags for states to match
	uint32	local_ip[4];		// On OP_QueryRemoteConnection, this is the IP of the remote system
	uint32	remote_ip[4];		// When querying a listening port, remote is not used
	uint16	local_port;
	uint16	remote_port;
};
struct query_sock_response {
	uint64	clientid;		// used by netidd for peer comm
	uint64	queryid;		// available for client use
	uint8	flags;
	pid_t	pid;
	uid_t	uid;			// effective uid
	gid_t	gid;			// effective gid
	uint32	nsgids;
	gid_t	sgids[0];
};
#pragma pack()
