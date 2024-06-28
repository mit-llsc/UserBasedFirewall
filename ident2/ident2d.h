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
#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif
#include <sys/socket.h>

#include "types.h"
#include "ident2d_api.h"

//#define DEBUG_LOG	// spam the log
//#define FINDSOCKET_DEBUG // enables printing socket info to stdout

#define IDENT2D_CONFIG	"/etc/ident2d.conf"
#define PIDFILE			"/var/run/ident2d.pid"
#define LOGFILE			"/var/log/ident2d.log"
#define DEFAULT_IDENT2_UDP_PORT	99
#define IDENT2D_CONFIG_MAX_IPRANGES 100

#define CLIENTYPE_SHUTDOWN	0
#define CLIENTYPE_PEERSOCK	1
#define CLIENTYPE_CLIENT	2
#define CLIENTYPE_PRECACHE	3
struct client {
	struct client *next;
	struct client *prev;
	uint8 type;
	uint64 id;
	int s;
	volatile int refcount;
};
/*
refcount stragegy (for type == client):
-Use atomic increment/decrement
--Callers of decrement must check for zero, and free object if refcount hits zero
--Callers of increment must hold a refcount already to be safe
-The two initial refcounts are clientlist and epoll
--holding epoll ONESHOT trigger works
--holding client_list mutex works
*/

int openlog(const char* fn);
void closelog();
void logit(const char* format, ...);
void logit_buffer(void* buf, uint32 size);

// For all functions, 0=success / check passed, positive=warning / check failed, negative=error (disconnect client)
//int SendMsgToClient(struct client *c, char opcode, void* buffer, int len);
#define SendMsgToClient(c, opcode, buffer, len) SendMsgToSock(c->s, NULL, opcode, buffer, len, NULL, 0)
int SendMsgToSock(int sock, struct sockaddr_in6 *sockaddr, char opcode, void* buffer1, int len1, void* buffer2, int len2);

int Process_QueryLocalConnection(uint8 reply_opcode, const char* clientIDstring, char *buffer, int len, int sock, struct sockaddr_in6* sockaddr, uint32 max_nsgids);
void ProcessClientPacket(struct client *c, char *buffer, int len
#ifdef DEBUG_LOG
, struct ucred *cred
#endif
);
void ProcessPeerPacket(struct sockaddr_in6* sockaddr, char *buffer, int len);
struct client * FindClientByID(uint64 clientID);

int open_netlink_socket();
void close_netlink_socket();
int find_socket(uint8 ip_version, uint8 protocol, void* lIP, uint16 lPort, void* rIP, uint16 rPort, uint32 tcp_states, uint32* oINode, uid_t* oUID, pid_t* oPID, int want_pid_if_root);
int GetProcessInfo(pid_t pid, uid_t* euid, gid_t* egid, uint32* nsgids, gid_t* sgids, uint32 sgids_size);
int CheckAllowedPeer(uint8 ip_version, void* IP);

int FindPIDFromSocketInode_initcache();
void FindPIDFromSocketInode_cleanup();
int FindPIDFromSocketInode_addcache(pid_t pid, int fdno);
#define CACHE_HINT_NORMAL	0	// normal or unknown, best for listening sockets
#define CACHE_HINT_ONESHOT	1	// best for outbound connecting sockets, likelyhood of being queried again later is near-nil
#define CACHE_MATCHTYPE_NETINFO	2	// Match network info (TCP listening sockets only)
#define CACHE_MATCHTYPE_INODE	3	// match socket inode number
pid_t FindPIDFromSocketInode(int matchtype, uint8 cachehint, uint32 inode, uid_t uid, uint8 ip_version, uint8 protocol, void* ip, uint16 port, uint32* oINode, uid_t* oUID);
pid_t FindPIDFromSocketInode_nocache(uint32 inode, int *pfdno);

struct PeerIPRange {
	uint8	ip_version; // 4 | 6
	uint8	ip[16];
	uint8	mask; // 0-128
};

struct ident2d_config_struct {
	int NumThreads;
	char DropPriv_User[32];
	uint16 UDPPort;
	char SocketGroup[32];
	int SocketOther;
	int AllowPrecache;
	struct PeerIPRange AllowedPeerIPRanges[IDENT2D_CONFIG_MAX_IPRANGES];
};
int load_config(const char* configfile, struct ident2d_config_struct* config);
