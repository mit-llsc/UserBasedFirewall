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
#ifndef TCP_STATES_H
#define TCP_STATES_H

#define TCP_MAX_STATES  (TCP_CLOSING + 1)
#define TCP_STATE_MASK	0xF

#define TCPF_ESTABLISHED  (1 << 1)
#define TCPF_SYN_SENT	  (1 << 2)
#define TCPF_SYN_RECV	  (1 << 3)
#define TCPF_FIN_WAIT1	  (1 << 4)
#define TCPF_FIN_WAIT2	  (1 << 5)
#define TCPF_TIME_WAIT	  (1 << 6)
#define TCPF_CLOSE        (1 << 7)
#define TCPF_CLOSE_WAIT	  (1 << 8)
#define TCPF_LAST_ACK	  (1 << 9)
#define TCPF_LISTEN       (1 << 10)
#define TCPF_CLOSING	  (1 << 11) 
#define TCPF_STATES_ALL   ((1 << TCP_MAX_STATES)-1)

#endif
