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
typedef u_int8_t uint8;
typedef u_int16_t uint16;
typedef u_int32_t uint32;
typedef u_int64_t uint64;

#include "ident2d_api.h"
#include "tcp_states.h"

#define IDENT2_LOCAL 1
#define IDENT2_REMOTE 2

#define SYNCIDENT2_WAIT_SEC 0
#define SYNCIDENT2_WAIT_NSEC 300000000 // 300ms
#define SYNCIDENT2_NUM_RETRIES 2 // includes initial "try" (0 and 1 are effectively the same setting - single attempt)

int InitSyncIdent2d();
struct query_sock_response * SyncAskIdent2(uint8 LocalOrRemote, uint8 flags, uint8 ip_version, uint8 protocol, void* lIP, uint16 lPort, void* rIP, uint16 rPort, uint32 tcp_states);
int ConnectIdent2Sock();
