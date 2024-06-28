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
#include <pwd.h>

#include "netidd.h"

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

// negative=error: -1 = generic error; -2 = number conversion failed; -3 = name not found
int config_get_uid(char* struid, uid_t* out_uid) {
	struct passwd *pwd;
	char *errcheck;

	if (struid[0] >= '0' && struid[0] < '9') {
		// raw number
		*out_uid = strtol(struid, &errcheck, 10);
		if (errcheck == NULL || (errcheck[0] != '\0' && errcheck[0] != '\n'))
			return -2;
		return 0;
	}
	if ((pwd = getpwnam(struid)) == NULL)
		return -3;
	*out_uid = pwd->pw_uid;
	return 0;
}

// negative=error: -1 = generic error; -2 = too many ranges found, results truncated, -3 = invalid range
int config_process_uid_range(char* buffer, struct netid_config_uid_range *ranges, uint32 maxranges) {
	uint32 item = 0;
	int r;
	char *str = NULL, *max = NULL;

	if ((str = strtok(buffer, ",")) == NULL) {
		logit("config_process_uid_range: Error: first call to strtok() failed.\n");
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

		if (str[0] >= '0' && str[0] <= '9' && (max = strchr(str, '-')) != NULL) {
			max[0] ='\0';
			max++;
		}
		if ((r = config_get_uid(str, &ranges[item].min)) != 0) {
			logit("config_process_uid_range: Error: config_get_uid(min=%s) failed. r=%i\n", str, r);
			return -1;
		}
		if (max) {
			if ((r = config_get_uid(str, &ranges[item].max)) != 0) {
				logit("config_process_uid_range: Error: config_get_uid(max=%s) failed. r=%i\n", max, r);
				return -1;
			}
		}
		else
			ranges[item].max = ranges[item].min;

		if (ranges[item].min > ranges[item].max) {
			logit("config_process_uid_range: Error: min (%i) > max (%i) for item#%i.\n", ranges[item].min, ranges[item].max, item);
			return -3;
		}

		item++;
	} while ((str = strtok(NULL, ",")));
	return 0;
}

//   negative=error: -1 = generic error, -2 = config file not found
int load_config(const char* configfile, struct netid_config_struct* config) {
	int retval = -1, r;
	uint32 linenum;
	char buffer[4096], *errcheck;
	FILE* f = NULL;

	memset(config, 0, sizeof(struct netid_config_struct));
	config->NoAnswer_SilentDrop_TimeoutMS = DEFAULT_SILENT_DROP_TIMEOUT;
	config->NetfilterQueueNum = DEFAULT_QUEUE_NUMBER;
	for (uint32 x=0; x<NETID_CONFIG_MAX_UIDS; x++) {
		config->ExemptListenUIDs[x].min = 1;
		config->ExemptConnectUIDs[x].min = 1;
	}

	if ((f = fopen(configfile, "r")) == NULL) {
		logit("read_config: failed to open file: '%s'. errno=%i (%s)\n", configfile, errno, strerror(errno));
		retval = -2;
		goto cleanup;
	}

//int read_config(const char* configfile, const char* name, char* value, ssize_t buffersize) {
//int read_config(FILE* f, const char* name, char* value, ssize_t buffersize, uint32* foundatlinenum) {
	// DropPriv_User
	r = read_config(f, "DropPriv_User", config->DropPriv_User, sizeof(config->DropPriv_User), NULL);
	if (!(r == 0 || r == -2)) {
		fprintf(stderr, "read_config(DropPriv_User) failed. r=%i.\n", r);
		goto cleanup;
	}

	fseek(f, 0, SEEK_SET);
	// ExemptListenUIDs
	r = read_config(f, "ExemptListenUIDs", buffer, sizeof(buffer), &linenum);
	if (!(r == 0 || r == -2)) {
		fprintf(stderr, "read_config(ExemptListenUIDs) failed. r=%i.\n", r);
		goto cleanup;
	}
	#ifdef DEBUG_LOG
		logit("load_config: DEBUG: ExemptListenUIDs r=%i\n", r);
	#endif
	if (r == 0) {
		#ifdef DEBUG_LOG
			logit("load_config: DEBUG: ExemptListenUIDs: %s\n", buffer);
		#endif
		if ((r = config_process_uid_range(buffer, config->ExemptListenUIDs, NETID_CONFIG_MAX_UIDS)) != 0) {
			fprintf(stderr, "config_process_uid_range(ExemptListenUIDs) failed. r=%i.\n", r);
			goto cleanup;
		}
	}

	fseek(f, 0, SEEK_SET);
	// ExemptConnectUIDs
	r = read_config(f, "ExemptConnectUIDs", buffer, sizeof(buffer), &linenum);
	if (!(r == 0 || r == -2)) {
		fprintf(stderr, "read_config(ExemptConnectUIDs) failed. r=%i.\n", r);
		goto cleanup;
	}
	#ifdef DEBUG_LOG
		logit("load_config: DEBUG: ExemptConnectUIDs r=%i\n", r);
	#endif
	if (r == 0) {
		#ifdef DEBUG_LOG
			logit("load_config: DEBUG: ExemptConnectUIDs: %s\n", buffer);
		#endif
		if ((r = config_process_uid_range(buffer, config->ExemptConnectUIDs, NETID_CONFIG_MAX_UIDS)) != 0) {
			fprintf(stderr, "config_process_uid_range(ExemptConnectUIDs) failed. r=%i.\n", r);
			goto cleanup;
		}
	}

	fseek(f, 0, SEEK_SET);
	// NoAnswer_SilentDrop_TimeoutMS
	r = read_config(f, "NoAnswer_SilentDrop_TimeoutMS", buffer, sizeof(buffer), &linenum);
	if (!(r == 0 || r == -2)) {
		fprintf(stderr, "read_config(NoAnswer_SilentDrop_TimeoutMS) failed. r=%i.\n", r);
		goto cleanup;
	}
	if (r == 0) {
		config->NoAnswer_SilentDrop_TimeoutMS = strtol(buffer, &errcheck, 10);
		if (errcheck == NULL || (errcheck[0] != '\0' && errcheck[0] != '\n')) {
			logit("Error: failed to convert config->NoAnswer_SilentDrop_TimeoutMS from string '%s' to long\n", buffer);
			goto cleanup;
		}
	}
	if (config->NoAnswer_SilentDrop_TimeoutMS == 0) {
		logit("Error: Invalid value for config->NoAnswer_SilentDrop_TimeoutMS; cannot be zero\n");
		goto cleanup;
	}

	fseek(f, 0, SEEK_SET);
	//NetfilterQueueNum
	r = read_config(f, "NetfilterQueueNum", buffer, sizeof(buffer), &linenum);
	if (!(r == 0 || r == -2)) {
		fprintf(stderr, "read_config(NetfilterQueueNum) failed. r=%i.\n", r);
		goto cleanup;
	}
	if (r == 0) {
		config->NetfilterQueueNum = strtol(buffer, &errcheck, 10);
		if (errcheck == NULL || (errcheck[0] != '\0' && errcheck[0] != '\n')) {
			logit("Error: failed to convert config->NetfilterQueueNum from string '%s' to long\n", buffer);
			goto cleanup;
		}
	}

	fseek(f, 0, SEEK_SET);
	//GetConnectorGroupsFromUserDB
	r = read_config(f, "GetConnectorGroupsFromUserDB", buffer, sizeof(buffer), &linenum);
	if (!(r == 0 || r == -2)) {
		fprintf(stderr, "read_config(GetConnectorGroupsFromUserDB) failed. r=%i.\n", r);
		goto cleanup;
	}
	if (r == 0) {
		config->GetConnectorGroupsFromUserDB = strtol(buffer, &errcheck, 10);
		if (errcheck == NULL || (errcheck[0] != '\0' && errcheck[0] != '\n') || config->GetConnectorGroupsFromUserDB < 0 || config->GetConnectorGroupsFromUserDB > 1) {
			logit("Error: failed to convert config->GetConnectorGroupsFromUserDB from string '%s' to boolean\n", buffer);
			goto cleanup;
		}
	}

	fseek(f, 0, SEEK_SET);
	// LogDeniesToSyslog
	r = read_config(f, "LogDeniesToSyslog", buffer, sizeof(buffer), &linenum);
	if (!(r == 0 || r == -2)) {
		fprintf(stderr, "read_config(LogDeniesToSyslog) failed. r=%i.\n", r);
		goto cleanup;
	}
	if (r == 0) {
		if (buffer[0] == '1' && buffer[1] == '\0') {
			config->LogDeniesToSyslog = 1;
		}
		else if (buffer[0] == '0' && buffer[1] == '\0') {
			config->LogDeniesToSyslog = 0;
		}
		else {
			fprintf(stderr, "Error: LogDeniesToSyslog is not '0' or '1'. LogDeniesToSyslog='%s'\n", buffer);
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
