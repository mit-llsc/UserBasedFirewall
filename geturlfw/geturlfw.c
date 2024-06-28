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
#include <sys/types.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <linux/securebits.h>

#ifdef ubuntu
#include "../ident2/SyncAskIdent2.h"
#define URLFW_DIR "/etc/apache2/urlfw/fw/"
#else
#include "../ident2/SyncAskIdent2.h"
#define URLFW_DIR "/etc/httpd/urlfw/fw/"
#endif

#define MAX_DST_LENGTH 1024
#define STDIN_BUF_LENGTH 1024

int CheckNameSanity(const char* name);
int IsConnectionOK(struct query_sock_response *qsr, struct stat *st);

void TermAtNewline(char* s) {
	int x;
	for (x=0; s[x]; x++) {
		if (s[x] == '\n' || s[x] == '\r') {
			s[x] = '\0';
			break;
		}
	}
}

int main() {
	int retval = -1;
	char *username = NULL, *fwname = NULL, *fwdst_scheme = NULL, *fwdst_auth = NULL, *fwdst_host = NULL, *fwdst_port = NULL, *fwdst_path = NULL; // just pointers
	char *stdinbuf = NULL, *fwdst = NULL; // malloc'd
	struct passwd *userinfo = NULL;
	FILE *f = NULL;
	int access_ret, urlfw_dir_fd = -1, fd = -1;
	struct stat st;
	struct hostent *he = NULL;
	struct in_addr *in = NULL;
	char *errcheck;
	long long_port;
	uint16 port;
	struct query_sock_response *qsr = NULL;
	struct group *grp = NULL;
	gid_t ident2_gid;
	cap_t caps;
	cap_value_t kept_caps[] = {
		CAP_DAC_READ_SEARCH, // actually read fw file
		CAP_SETUID, // set uid for eaccess check
		CAP_SETGID, // set gid for eaccess check
	};

	// make sure we're root and/or take advantage of setuid bit
#pragma GCC diagnostic ignored "-Wunused-result"
	setresuid(0, 0, 0);
	setresgid(0, 0, 0);
#pragma GCC diagnostic warning "-Wunused-result"
	if (getuid() != 0) {
		fprintf(stderr, "Error: not root.\n");
		goto cleanup;
	}

	if ((grp = getgrnam("ident2")) == NULL) {
		fprintf(stderr, "getgrnam(ident2) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	ident2_gid = grp->gr_gid;

	// Drop caps
	if (prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NOROOT_LOCKED, 0, 0, 0) != 0) {
		fprintf(stderr, "prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NOROOT_LOCKED) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); // doesn't exist on all kernels, so fire and forget
	if ((caps = cap_init()) == NULL) {
		fprintf(stderr, "cap_init() failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	if (cap_clear(caps) != 0) {
		fprintf(stderr, "cap_clear() failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	if (cap_set_flag(caps, CAP_EFFECTIVE, sizeof(kept_caps)/sizeof(cap_value_t), kept_caps, CAP_SET) != 0) {
		fprintf(stderr, "cap_set_flag(CAP_EFFECTIVE) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	if (cap_set_flag(caps, CAP_PERMITTED, sizeof(kept_caps)/sizeof(cap_value_t), kept_caps, CAP_SET) != 0) {
		fprintf(stderr, "cap_set_flag(CAP_PERMITTED) failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	if (cap_set_proc(caps) != 0) {
		fprintf(stderr, "cap_set_proc()[1] failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}
	cap_free(caps);

	if (!InitSyncIdent2d()) { // set sigio handler
		fprintf(stderr, "InitSyncIdent2d() failed. errno=%i (%s)\n", errno, strerror(errno));
		goto cleanup;
	}

	// turn off stdin & stdout buffering
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

	// alloc our buffers
	if ((stdinbuf = malloc(STDIN_BUF_LENGTH)) == NULL) {
		fprintf(stderr, "Error: malloc(stdinbuf) failed.\n");
		goto cleanup;
	}
	if ((fwdst = malloc(MAX_DST_LENGTH)) == NULL) {
		fprintf(stderr, "Error: malloc(fwdst) failed.\n");
		goto cleanup;
	}

	// loop till we die
	while (fgets(stdinbuf, STDIN_BUF_LENGTH, stdin)) {
		// cleanup from previous loop, if necessary
		username = NULL;
		fwname = NULL;
		fwdst_scheme = NULL;
		fwdst_auth = NULL;
		fwdst_host = NULL;
		fwdst_port = NULL;
		fwdst_path = NULL;
		if (urlfw_dir_fd >= 0)
			close(urlfw_dir_fd);
		urlfw_dir_fd = -1;
		if (fd >= 0)
			close(fd);
		fd = -1;
		if (f)
			fclose(f);
		f = NULL;
		memset(fwdst, 0, MAX_DST_LENGTH);
		if (geteuid() != 0 || getegid() != 0) {
			if (setresuid(0, 0, 0)) {
				fprintf(stderr, "Error: setresuid(0) failed. errno=%i (%s)\n", errno, strerror(errno));
				goto cleanup;
			}
			if (setresgid(0, 0, 0)) {
				fprintf(stderr, "Error: setresgid(0) failed. errno=%i (%s)\n", errno, strerror(errno));
				goto cleanup;
			}
			if (setgroups(1, &ident2_gid) != 0) {
				fprintf(stderr, "Error: setgroups(ident2_gid) failed. errno=%i (%s)\n", errno, strerror(errno));
				goto cleanup;
			}
		}

		// split the stdin line into username & urlfw name
		TermAtNewline(stdinbuf);
		if ((username = strtok(stdinbuf, "/")) == NULL) {
			fprintf(stderr, "Error: strtok(username) failed.\n");
			goto cleanup;
		}
		if (!CheckNameSanity(username)) {
			fprintf(stderr, "Warn: username failed sanity check.\n");
			fprintf(stdout, "NULL\n");
			continue;
		}
		if ((fwname = strtok(NULL, "/")) == NULL) {
			fprintf(stderr, "Warn: strtok(fwname) failed.\n");
			fprintf(stdout, "NULL\n");
			continue;
		}
		if (!CheckNameSanity(fwname)) {
			fprintf(stderr, "Warn: fwname failed sanity check.\n");
			fprintf(stdout, "NULL\n");
			continue;
		}

		if ((urlfw_dir_fd = open(URLFW_DIR, O_RDONLY | O_DIRECTORY)) < 0) {
			fprintf(stderr, "Warn: Failed to open URLFW_DIR=%s. errno=%i (%s)\n", URLFW_DIR, errno, strerror(errno));
			fprintf(stdout, "NULL\n");
			continue;
		}

		// find the uid, gid & groups of the user and set them for FS access
		if ((userinfo = getpwnam(username)) == NULL) {
			fprintf(stderr, "Warn: getpwnam failed. User not exist?\n");
			fprintf(stdout, "NULL\n");
			continue;
		}
		if (setresgid(userinfo->pw_gid, userinfo->pw_gid, -1)) {
			fprintf(stderr, "Error: setresgid failed.\n");
			goto cleanup;
		}
		if (initgroups(username, userinfo->pw_gid)) {
			fprintf(stderr, "Error: initgroups failed.\n");
			goto cleanup;
		}
		if (setresuid(userinfo->pw_uid, userinfo->pw_uid, -1)) {
			fprintf(stderr, "Error: setresuid failed.\n");
			goto cleanup;
		}

		// check if the user we're now impersonating can access the file
		// So AT_EACCESS seems to be completely vestigal, it was added to glibc but never merged into the kernel, doesn't work.
		access_ret = faccessat(urlfw_dir_fd, fwname, X_OK, 0);

		// switch away from the user's identity
		if (setresuid(0, 0, 0)) {
			fprintf(stderr, "Error: setresuid(0) failed.\n");
			goto cleanup;
		}
		if (setresgid(0, 0, 0)) {
			fprintf(stderr, "Error: setresgid(0) failed.\n");
			goto cleanup;
		}
		if (setgroups(1, &ident2_gid) != 0) {
			fprintf(stderr, "Error: setgroups(ident2_gid) failed. errno=%i (%s)\n", errno, strerror(errno));
			goto cleanup;
		}

		// Soooo... how did that go?
		if (access_ret != 0) {
			// no access or file not exist, not even worthy of a WARN
			fprintf(stdout, "NULL\n");
			close(urlfw_dir_fd);
			urlfw_dir_fd = -1;
			continue;
		}
		
		// open the foward file with openat: avoids any string handling, yay!
		if ((fd = openat(urlfw_dir_fd, fwname, O_RDONLY)) < 0) {
			// far too common to warn about
			//fprintf(stderr, "Warn: Failed to open forward file. errno=%i (%s)\n", errno, strerror(errno));
			fprintf(stdout, "NULL\n");
			if (urlfw_dir_fd >= 0)
				close(urlfw_dir_fd);
			urlfw_dir_fd = -1;
			continue;
		}
		if (fstat(fd, &st) != 0) {
			fprintf(stderr, "Warn: fstat failed. errno=%i (%s)\n", errno, strerror(errno));
			fprintf(stdout, "NULL\n");
			continue;
		}
		if (st.st_size == 0) { // well nevermind then
			fprintf(stdout, "NULL\n");
			close(fd);
			fd = -1;
			close(urlfw_dir_fd);
			urlfw_dir_fd = -1;
			continue;
		}
		// convert our fd to a stream handle
		if ((f = fdopen(fd, "r")) == NULL) {
			fprintf(stdout, "NULL\n");
			continue;
		}
		// read in the forward destination (also checks that it exists)
		if (fgets(fwdst, MAX_DST_LENGTH, f) == NULL) {
			fprintf(stderr, "Warn: fgets failed\n");
			fprintf(stdout, "NULL\n");
			continue;
		}

		fclose(f);
		f = NULL;
		close(fd);
		fd = -1;
		close(urlfw_dir_fd);
		urlfw_dir_fd = -1;

		TermAtNewline(fwdst);

		if (st.st_uid == 0 && (st.st_mode & S_ISVTX)) {
			// root sez: just do it.
			// output the result to httpd
			fprintf(stdout, "%s\n", fwdst);
			continue;
		}

		// Parse URL to get remote host/IP and port
		if (strncmp(fwdst, "http://", 7) == 0) {
			fwdst_scheme = "http";
			port = 80;
			fwdst_host = strtok(&fwdst[7], "/");
		}
		else if (strncmp(fwdst, "https://", 8) == 0) {
			fwdst_scheme = "https";
			port = 443;
			fwdst_host = strtok(&fwdst[8], "/");
		}
		else {
			fprintf(stdout, "NULL\n");
			continue;
		}
		if (fwdst_host == NULL) {
			fprintf(stdout, "NULL\n");
			continue;
		}
		fwdst_path = strtok(NULL, "");

		// find authentication string, if any
		for (ssize_t x=0; fwdst_host[x]; x++) {
			if (fwdst_host[x] == '@') {
				fwdst_auth = fwdst_host;
				fwdst_host[x] = '\0';
				fwdst_host = &fwdst_host[x+1];
				break;
			}
		}

		// find port number
		fwdst_port = NULL;
		for (ssize_t x=strlen(fwdst_host)-1; x>0; x--) {
			if (fwdst_host[x] == ':') {
				fwdst_port = &fwdst_host[x+1];
				fwdst_host[x] = '\0';
				break;
			}
			if (fwdst_host[x] < '0' || fwdst_host[x] > '9')
				break;
		}

		// lookup IP address of target
		if ((he = gethostbyname2(fwdst_host, AF_INET)) == NULL) {
			fprintf(stderr, "Warn: gethostbyname2(fwdst_host) failed. errno=%i (%s)\n", errno, strerror(errno));
			fprintf(stdout, "NULL\n");
			continue;
		}
		if (he->h_length == 0) {
			fprintf(stderr, "Warn: gethostbyname2(fwdst_host) returned no entries.\n");
			fprintf(stdout, "NULL\n");
			continue;
		}
		if ((in = (struct in_addr *) he->h_addr_list[0]) == NULL) {
			fprintf(stderr, "Warn: gethostbyname2(fwdst_host) returned no data.\n");
			fprintf(stdout, "NULL\n");
			continue;
		}

		// parse port number
		if (fwdst_port) {
			long_port = strtol(fwdst_port, &errcheck, 10);
			if (errcheck == NULL || (errcheck[0] != '\0' && errcheck[0] != '\n')) {
				fprintf(stderr, "Warn: Failed to parse port number, strtol had leftover data.\n");
				fprintf(stdout, "NULL\n");
				continue;
			}
			if (long_port < 0 || long_port > 0xFFFF) {
				fprintf(stderr, "Warn: Failed to parse port number, strtol return out of range for a uint16.\n");
				fprintf(stdout, "NULL\n");
				continue;
			}
			port = (uint16) long_port;
		}

#ifdef DEBUG_LOG
		fprintf(stderr, "DEBUG: IP=%s, port=%i\n", inet_ntoa(*in), port);
#endif

		// Ask ident2 who owns the far port
		if ((qsr = SyncAskIdent2(IDENT2_REMOTE, QS_Flag_PGIDInfo, 4, IPPROTO_TCP, &in->s_addr, port, NULL, 0, TCPF_LISTEN)) == NULL) {
			fprintf(stderr, "Warn: SyncAskIdent2 returned NULL. errno=%i (%s)\n", errno, strerror(errno));
			fprintf(stdout, "NULL\n");
			continue;
		}

		// make a decision
		if (IsConnectionOK(qsr, &st)) {
			if (fwdst_auth)
				fprintf(stdout, "%s://%s@%s:%hu%s%s\n", fwdst_scheme, fwdst_auth, inet_ntoa(*in), port, fwdst_path ? "/" : "", fwdst_path ? fwdst_path : "");
			else
				fprintf(stdout, "%s://%s:%hu%s%s\n", fwdst_scheme, inet_ntoa(*in), port, fwdst_path ? "/" : "", fwdst_path ? fwdst_path : "");
		}
		else
			fprintf(stdout, "NULL\n");
	}

	retval = 0;
cleanup:
	if (urlfw_dir_fd >= 0)
		close(urlfw_dir_fd);
	urlfw_dir_fd = -1;
	if (fd >= 0)
		close(fd);
	fd = -1;
	if (f)
		fclose(f);
	f = NULL;

	if (stdinbuf)
		free(stdinbuf);
	stdinbuf = NULL;
	if (fwdst)
		free(fwdst);
	fwdst = NULL;

	return retval;
}

int IsConnectionOK(struct query_sock_response *qsr, struct stat *st) {
	if (!(qsr->flags & QS_Flag_HaveAnswer)) {
		fprintf(stderr, "Notice: No answer in ident2 response.\n");
		return 0;
	}
	if (qsr->uid == st->st_uid && (st->st_mode & (S_IWGRP | S_IWOTH)) == 0)
		return 1;
	if (!(qsr->flags & QS_Flag_PGIDInfo)) {
//		fprintf(stderr, "Notice: No primary GID info in ident2 response.\n");
		return 0;
	}
	if (qsr->gid == st->st_gid)
		return 1;
	return 0;
}

int CheckNameSanity(const char* name) {
	for (ssize_t x=0; name[x]; x++) {
		if ( (name[x] >= 'a' && name[x] <= 'z') || (name[x] >= 'A' && name[x] <= 'Z') || (name[x] >= '0' && name[x] <= '9') || name[x] == '.' || name[x] == '_' || name[x] == '-')
			continue;
		return 0;
	}
	return 1;
}

