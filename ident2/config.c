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
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ident2d.h"

/* value can be null for buffer size discovery
   0=success
   negative=error: -1 = generic error, -2 = config entry not found
   positive=buffer too small, needed size returned
*/
int read_config(FILE* f, const char* name, char* value, ssize_t buffersize, uint32* foundatlinenum) {
	uint32 linenum;
	char line_buffer[16384], *line = NULL, *namepart, *valuepart;

	linenum = 0;
	while (fgets(line_buffer, sizeof(line_buffer), f) != NULL) {
		linenum++;
		line = line_buffer;
		for (; line[0] == ' ' || line[0] == '\t'; line++); // advance past any leading whitespace
		for (size_t x=0; line[x]; x++) { // kill the newline markers
			if (line[x] == '\r' || line[x] == '\n') {
				line[x] = 0;
				break;
			}
		}
		if (line[0] == 0 || line[0] == '#') // blank line / comment line
			continue;

		if ((namepart = strtok(line, "=")) == NULL) {
			logit("read_config: line #%i of the config does not contain an equals sign.\n", linenum);
			return -1;
		}

		valuepart = strtok(NULL, "=");

		for (ssize_t x=strlen(namepart)-1; x >= 0; x--) { // kill any trailing whitespace
			if (namepart[x] == ' ' || namepart[x] == '\t')
				namepart[x] = '\0';
			else
				break;
		}
		for (; valuepart[0] == ' ' || valuepart[0] == '\t'; valuepart++); // advance past any leading whitespace
		for (ssize_t x=strlen(valuepart)-1; x >= 0; x--) { // kill any trailing whitespace
			if (valuepart[x] == ' ' || valuepart[x] == '\t')
				valuepart[x] = '\0';
			else
				break;
		}

		if (strcasecmp(name, namepart) == 0) {
			if (value == NULL || (strlen(valuepart)+1) > buffersize) {
				return (strlen(valuepart)+1);
			}
			
			strcpy(value, valuepart);
			if (foundatlinenum)
				*foundatlinenum = linenum;
			return 0;
		}
	}

	// reached end of file without a match...
	return -2;
}

// negative=error: -1 = generic error; -2 = too many ranges found, results truncated, -3 = invalid range
int config_process_peerip_range(char* buffer, struct PeerIPRange *ranges, uint32 maxranges) {
	uint32 item = 0;
	char *str = NULL, *mask = NULL, *errcheck = NULL;

//	logit("config_process_peerip_range: DEBUG: buffer='%s'.\n", buffer);
	if ((str = strtok(buffer, ",")) == NULL) {
		logit("config_process_peerip_range: Error: first call to strtok() failed.\n");
		return -1;
	}
	do {
		if (item >= maxranges)
			return -2;
		for (; str[0] == ' ' || str[0] == '\t'; str++); // advance past any leading whitespace
		for (ssize_t x=strlen(str)-1; x >= 0; x--) { // kill any trailing whitespace
			if (str[x] == ' ' || str[x] == '\t')
				str[x] = '\0';
			else
				break;
		}
//		logit("config_process_peerip_range: DEBUG: str='%s'.\n", str);

		if ((mask = strchr(str, '/')) != NULL) {
			mask[0] ='\0';
			mask++;
//			logit("config_process_peerip_range: DEBUG: mask='%s'.\n", mask);
		}
		
		if (inet_pton(AF_INET, str, ranges[item].ip) == 1) {
			ranges[item].ip_version = 4;
		}
		else if (inet_pton(AF_INET6, str, ranges[item].ip) == 1) {
			ranges[item].ip_version = 6;
		}
		else {
			logit("config_process_peerip_range: Error: inet_pton(ip=%s) failed.\n", str);
			return -1;
		}

		if (mask) {
			ranges[item].mask = strtol(mask, &errcheck, 10);
			if (errcheck == NULL || (errcheck[0] != '\0' && errcheck[0] != '\n')) {
				logit("config_process_peerip_range: Error: failed to convert mask from string '%s' to long\n", mask);
				return -1;
			}
			if ((ranges[item].ip_version == 4 && ranges[item].mask > 32) || (ranges[item].ip_version == 6 && ranges[item].mask > 128)) {
				logit("config_process_peerip_range: Error: mask > 32|128\n");
				return -1;
			}
//			logit("config_process_peerip_range: DEBUG: ip=%08x, bitmask=%08x, hb_ip=%08x.\n", ranges[item].ip, bitmask, ntohl(ranges[item].ip));
//			ranges[item].ip = htonl( ntohl(ranges[item].ip) & (0xFFFFFFFF << (32 - ranges[item].mask)) );
		}
		else
			ranges[item].mask = ranges[item].ip_version == 4 ? 32 : 128;

//		logit("config_process_peerip_range: DEBUG: done. IP=%s, mask=%i.\n", inet_ntoa(*((struct in_addr*) &ranges[item].ip)), ranges[item].mask);
		item++;
	} while ((str = strtok(NULL, ",")));
	return 0;
}

//   negative=error: -1 = generic error, -2 = config file not found
int load_config(const char* configfile, struct ident2d_config_struct* config) {
	int retval = -1, r;
	uint32 linenum;
	char buffer[4096], *errcheck;
	FILE* f = NULL;

	memset(config, 0, sizeof(struct ident2d_config_struct));
	config->UDPPort = DEFAULT_IDENT2_UDP_PORT;
	config->NumThreads = 4;
	for (uint32 x=0; x<IDENT2D_CONFIG_MAX_IPRANGES; x++) {
		config->AllowedPeerIPRanges[x].mask = 0xFF;
	}

	if ((f = fopen(configfile, "r")) == NULL) {
		logit("read_config: failed to open file: '%s'. errno=%i (%s)\n", configfile, errno, strerror(errno));
		retval = -2;
		goto cleanup;
	}

	// DropPriv_User
	r = read_config(f, "DropPriv_User", config->DropPriv_User, sizeof(config->DropPriv_User), NULL);
	if (!(r == 0 || r == -2)) {
		fprintf(stderr, "read_config(DropPriv_User) failed. r=%i.\n", r);
		goto cleanup;
	}

	fseek(f, 0, SEEK_SET);
	// UDPPort
	r = read_config(f, "UDPPort", buffer, sizeof(buffer), &linenum);
	if (!(r == 0 || r == -2)) {
		fprintf(stderr, "read_config(UDPPort) failed. r=%i.\n", r);
		goto cleanup;
	}
	if (r == 0) {
		config->UDPPort = strtol(buffer, &errcheck, 10);
		if (errcheck == NULL || (errcheck[0] != '\0' && errcheck[0] != '\n')) {
			logit("Error: failed to convert config->UDPPort from string '%s' to long\n", buffer);
			goto cleanup;
		}
	}
	if (config->UDPPort <= 0 || config->UDPPort >= 1024) {
		logit("Error: Invalid value for config->UDPPort; cannot be zero or >=1024\n");
		goto cleanup;
	}

	fseek(f, 0, SEEK_SET);
	// SocketGroup
	r = read_config(f, "SocketGroup", config->SocketGroup, sizeof(config->SocketGroup), NULL);
	if (!(r == 0 || r == -2)) {
		fprintf(stderr, "read_config(SocketGroup) failed. r=%i.\n", r);
		goto cleanup;
	}

	fseek(f, 0, SEEK_SET);
	// SocketOther
	r = read_config(f, "SocketOther", buffer, sizeof(buffer), &linenum);
	if (!(r == 0 || r == -2)) {
		fprintf(stderr, "read_config(SocketOther) failed. r=%i.\n", r);
		goto cleanup;
	}
	#ifdef DEBUG_LOG
		logit("load_config: DEBUG: SocketOther r=%i\n", r);
	#endif
	if (r == 0) {
		#ifdef DEBUG_LOG
			logit("load_config: DEBUG: SocketOther: %s\n", buffer);
		#endif
		if (buffer[0] == '1' && buffer[1] == '\0') {
			config->SocketOther = 1;
		}
		else if (buffer[0] == '0' && buffer[1] == '\0') {
			config->SocketOther = 0;
		}
		else {
			fprintf(stderr, "Error: SocketOther is not '0' or '1'. SocketOther='%s'\n", buffer);
			goto cleanup;
		}
	}

	fseek(f, 0, SEEK_SET);
	//AllowedPeerIPs
	r = read_config(f, "AllowedPeerIPs", buffer, sizeof(buffer), &linenum);
	if (!(r == 0 || r == -2)) {
		fprintf(stderr, "read_config(AllowedPeerIPs) failed. r=%i.\n", r);
		goto cleanup;
	}
	#ifdef DEBUG_LOG
		logit("load_config: DEBUG: AllowedPeerIPs r=%i\n", r);
	#endif
	if (r == 0) {
		#ifdef DEBUG_LOG
			logit("load_config: DEBUG: AllowedPeerIPs: %s\n", buffer);
		#endif
		if ((r = config_process_peerip_range(buffer, config->AllowedPeerIPRanges, IDENT2D_CONFIG_MAX_IPRANGES)) != 0) {
			fprintf(stderr, "config_process_peerip_range(AllowedPeerIPs) failed. r=%i.\n", r);
			goto cleanup;
		}
	}

	fseek(f, 0, SEEK_SET);
	//NumThreads
	r = read_config(f, "NumThreads", buffer, sizeof(buffer), &linenum);
	if (!(r == 0 || r == -2)) {
		fprintf(stderr, "read_config(NumThreads) failed. r=%i.\n", r);
		goto cleanup;
	}
	if (r == 0) {
		config->NumThreads = strtol(buffer, &errcheck, 10);
		if (errcheck == NULL || (errcheck[0] != '\0' && errcheck[0] != '\n')) {
			logit("Error: failed to convert config->NumThreads from string '%s' to long\n", buffer);
			goto cleanup;
		}
	}
	if (config->NumThreads <= 0 || config->NumThreads >= 4096) {
		logit("Error: Invalid value for config->NumThreads; cannot be zero or >=4096\n");
		goto cleanup;
	}

	fseek(f, 0, SEEK_SET);
	// AllowPrecache
	r = read_config(f, "AllowPrecache", buffer, sizeof(buffer), &linenum);
	if (!(r == 0 || r == -2)) {
		fprintf(stderr, "read_config(AllowPrecache) failed. r=%i.\n", r);
		goto cleanup;
	}
	#ifdef DEBUG_LOG
		logit("load_config: DEBUG: AllowPrecache r=%i\n", r);
	#endif
	if (r == 0) {
		#ifdef DEBUG_LOG
			logit("load_config: DEBUG: AllowPrecache: %s\n", buffer);
		#endif
		if (buffer[0] == '1' && buffer[1] == '\0') {
			config->AllowPrecache = 1;
		}
		else if (buffer[0] == '0' && buffer[1] == '\0') {
			config->AllowPrecache = 0;
		}
		else {
			fprintf(stderr, "Error: AllowPrecache is not '0' or '1'. AllowPrecache='%s'\n", buffer);
			goto cleanup;
		}
	}

	retval = 0;
cleanup:
	if (f)
		fclose(f);
	f = NULL;
	return retval;
}
