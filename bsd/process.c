/*
 * Copyright © 2026 Ole André Vadla Ravnås
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "process.h"

static void read_ids(FILE *status, const char *key, uint32_t ids[3]);
static uint64_t boot_time(void);

int
process_lookup(int32_t pid, struct process *process)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	FILE *stat = fopen(path, "r");
	if (stat == NULL) {
		return 1;
	}
	char line[1024];
	char *fields = (fgets(line, sizeof(line), stat) != NULL)
			? strrchr(line, ')')
			: NULL;
	fclose(stat);
	if (fields == NULL) {
		return 1;
	}

	memset(process, 0, sizeof(*process));
	process->pid = pid;
	char *comm = strchr(line, '(') + 1;
	snprintf(process->comm, sizeof(process->comm), "%.*s",
			(int)(fields - comm), comm);
	sscanf(fields + 2,
			"%*c %d %d %*d %*d %d %*u %*u %*u %*u %*u %*u %*u %*d "
			"%*d %*d %d %*d %*d %lu",
			&process->ppid, &process->pgid, &process->tpgid,
			&process->nice, &process->start_ticks);

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	FILE *status = fopen(path, "r");
	if (status == NULL) {
		return 1;
	}
	read_ids(status, "Uid:", process->uid);
	read_ids(status, "Gid:", process->gid);
	fclose(status);
	return 0;
}

void
process_start_time(const struct process *process, uint64_t *sec, uint64_t *usec)
{
	long ticks_per_second = sysconf(_SC_CLK_TCK);
	*sec = boot_time() + process->start_ticks / ticks_per_second;
	*usec = process->start_ticks % ticks_per_second * 1000000
			/ ticks_per_second;
}

static void
read_ids(FILE *status, const char *key, uint32_t ids[3])
{
	char line[256];
	size_t key_length = strlen(key);
	while (fgets(line, sizeof(line), status) != NULL) {
		if (strncmp(line, key, key_length) == 0) {
			sscanf(line + key_length, "%u %u %u", &ids[0], &ids[1],
					&ids[2]);
			return;
		}
	}
}

static uint64_t
boot_time(void)
{
	FILE *stat = fopen("/proc/stat", "r");
	char line[256];
	uint64_t btime = 0;
	while (fgets(line, sizeof(line), stat) != NULL) {
		if (sscanf(line, "btime %lu", &btime) == 1) {
			break;
		}
	}
	fclose(stat);
	return btime;
}
