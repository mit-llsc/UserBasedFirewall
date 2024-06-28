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
#include <stdint.h>
#include "types.h"
#include "../ident2d/ident2d_api.h"

/* Flags for NFQA_CFG_FLAGS */
#define NFQA_CFG_F_FAIL_OPEN			(1 << 0)
#define NFQA_CFG_F_CONNTRACK			(1 << 1)
#define NFQA_CFG_F_GSO				(1 << 2)
#define NFQA_CFG_F_UID_GID			(1 << 3)
#define NFQA_CFG_F_SECCTX			(1 << 4)
#define NFQA_CFG_F_MAX				(1 << 5)


#include <sys/socket.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

//#define DEBUG_LOG	// spam the log

#define NETIDD_CONFIG	"/etc/netidd.conf"
#define PIDFILE			"/var/run/netidd.pid"
#define LOGFILE			"/var/log/netidd.log"
#define NETID_ENVIRONMENT_VAR	"NETID_GROUP"
#define DEFAULT_SILENT_DROP_TIMEOUT		1000	// miliseconds
#define DEFAULT_QUEUE_NUMBER			 0

#define NETIDD_TCPFLAGS_REMOTE	TCPF_SYN_SENT
#define NETIDD_TCPFLAGS_LOCAL	TCPF_LISTEN
#define NETIDD_TCPFLAGS_NOSYN	TCPF_ESTABLISHED | TCPF_SYN_SENT | TCPF_FIN_WAIT1 | TCPF_FIN_WAIT2 | TCPF_TIME_WAIT | TCPF_CLOSE | TCPF_CLOSE_WAIT | TCPF_LAST_ACK | TCPF_CLOSING

struct packet {
	struct packet *next;
	struct packet *prev;
	uint64	ts;
	uint32	highQueryID;
	int		id;
	uint8*	packet_data;
	uint32	packet_data_size;
	sint8	have_local_answer; // 0 = waiting, 1 = answered w/user info, 2 = answered w/user+group info, 3 = answered w/user+group+process info, -1 = reply without answer, -2 = delayed asking
	sint8	have_remote_answer;
	pid_t	local_pid;
	uid_t	local_uid;
	gid_t	local_gid;
	uid_t	remote_uid;
	gid_t	remote_gid;
	uint32	remote_nsgids;
	gid_t*	remote_sgids;
	// fields for delayed query
	uint8	ip_version;
	uint8	protocol;
	uint32	saddr[4];
	uint16	sport;
	uint32	daddr[4];
	uint16	dport;
};

int openlogfile(const char* fn);
void closelogfile();
void logit(const char* format, ...);
void logit_buffer(void* buf, uint32 size);

int ConnectIdent2Sock();

struct packet * newpacket(int np_id, uint8* new_packetdata, uint32 new_packetdatasize);
void removepacket(struct packet **p);
void drop_all_packets(struct nfq_q_handle *nfqh);
uint64 GetPacketQueryID(struct packet *p);
struct packet * FindPacketByQueryID(uint64 queryID);
int MakeDecisionOnPacket(struct nfq_q_handle *nfqh, struct packet *p, uint8 opcode);

int AskIdent2(uint8 LocalOrRemote, uint64 queryID, uint8 ip_version, uint8 protocol, void* lIP, uint16 lPort, void* rIP, uint16 rPort, uint32 tcp_states);
int nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data);
int send_icmp_admin_prohibited(uint8 ip_version, uint8* packet, uint32 size);
int send_icmp_port_unreachable(uint8 ip_version, uint8* packet, uint32 size);
uint64 GetTS();

#define NETID_CONFIG_MAX_UIDS 20
struct netid_config_uid_range {
	uid_t min;
	uid_t max;
};
struct netid_config_struct {
	struct netid_config_uid_range ExemptListenUIDs[NETID_CONFIG_MAX_UIDS];
	struct netid_config_uid_range ExemptConnectUIDs[NETID_CONFIG_MAX_UIDS];
	int GetConnectorGroupsFromUserDB;
	uint32 NoAnswer_SilentDrop_TimeoutMS;
	uint16 NetfilterQueueNum;
	char DropPriv_User[32];
	int LogDeniesToSyslog;
};
int load_config(const char* configfile, struct netid_config_struct* config);
