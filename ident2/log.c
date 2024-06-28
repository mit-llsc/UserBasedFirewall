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
#define _XOPEN_SOURCE 500
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "types.h"

#define gettid() ((pid_t) syscall(SYS_gettid))

FILE* logfile = NULL;

int openlog(const char* fn) {
	if (logfile)
		return 0;
	if ((logfile = fopen(fn, "a")) == NULL)
		return -1;
	return 0;
}

void closelog() {
	if (logfile)
		fclose(logfile);
	logfile = NULL;
}

void logit(const char* format, ...) {
	va_list arg_ptr;
	unsigned int tmpAllocedSize = 16384;
	char* message;
	struct timespec t;

	if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) {
		t.tv_sec = 0;
		t.tv_nsec = 0;
	}

	va_start(arg_ptr, format);

	message = (char*) malloc(tmpAllocedSize);
	if (message == NULL)
		return;
	vsnprintf(message, tmpAllocedSize, format, arg_ptr);
	message[tmpAllocedSize-1] = 0;

	fprintf(logfile ? logfile : stderr, "[%8llu.%06lu, tid=%i] %s", (long long) t.tv_sec, t.tv_nsec / 1000, gettid(), message);
	free(message);
	fflush(logfile);
}

void AsciiDumpBuffer(FILE* iStream, uint8* buf, unsigned int size) {
	for (unsigned int x=0; x<size; x++) {
		if (x && (x % 8) == 0)
			fprintf(iStream, " ");
		if (buf[x] >= 32 && buf[x] <= 126)
			fprintf(iStream, "%c", buf[x]);
		else
			fprintf(iStream, ".");
	}
}
void HexDumpBuffer(FILE* iStream, uint8* buf, unsigned int size, char* newlinepad) {
	unsigned int x;
	if (newlinepad)
		fprintf(iStream, "%s", newlinepad);
	for (x=0; x<size; x++) {
		if (x && (x % 16) == 0) {
			fprintf(iStream, " ");
			AsciiDumpBuffer(iStream, &buf[x-16], 16);
			fprintf(iStream, "\n");
			if (newlinepad)
				fprintf(iStream, "%s", newlinepad);
		}
		else if (x % 16 == 8)
			fprintf(iStream, "- ");
		if ((x % 16) == 0)
			fprintf(iStream, "%4u: ", x);
		fprintf(iStream, "%02X ", buf[x]);
	}
	unsigned int tmp = 16 - (size%16);
	if (tmp != 16) {
		for (x=0; x<tmp; x++) {
			if (x == 7)
				fprintf(iStream, "  ");
			fprintf(iStream, "   ");
		}
	}
	tmp = size % 16;
	if (tmp == 0)
		tmp = 16;
	fprintf(iStream, " ");
	AsciiDumpBuffer(iStream, &buf[size - tmp], tmp);
	fprintf(iStream, "\n");
}

void logit_buffer(void* buf, unsigned int size) {
	HexDumpBuffer(logfile ? logfile : stderr, (uint8*) buf, size, NULL);
}
