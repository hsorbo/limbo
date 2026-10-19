/*
 * Copyright © 2021 Keegan Saunders
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

#include <mach/mach.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "handler.h"
#include "osfmk/task.h"
#include "process.h"
#include "xnu-errno.h"

#define PROC_INFO_CALL_PIDINFO         0x2
#define PROC_INFO_CALL_SETCONTROL      0x5
#define PROC_INFO_CALL_SET_DYLD_IMAGES 0xf

#define PROC_SELFSET_THREADNAME 2

#define PROC_PIDTBSDINFO           3
#define PROC_PIDT_SHORTBSDINFO     13
#define PROC_PIDUNIQIDENTIFIERINFO 17

#define SRUN           2
#define PROC_FLAG_LP64 0x10

struct proc_bsdshortinfo {
	uint32_t pbsi_pid;
	uint32_t pbsi_ppid;
	uint32_t pbsi_pgid;
	uint32_t pbsi_status;
	char pbsi_comm[16];
	uint32_t pbsi_flags;
	uint32_t pbsi_uid;
	uint32_t pbsi_gid;
	uint32_t pbsi_ruid;
	uint32_t pbsi_rgid;
	uint32_t pbsi_svuid;
	uint32_t pbsi_svgid;
	uint32_t pbsi_rfu;
};

struct proc_uniqidentifierinfo {
	uint8_t p_uuid[16];
	uint64_t p_uniqueid;
	uint64_t p_puniqueid;
	int32_t p_idversion;
	uint32_t p_reserve2;
	uint64_t p_reserve3;
	uint64_t p_reserve4;
};

struct proc_bsdinfo {
	uint32_t pbi_flags;
	uint32_t pbi_status;
	uint32_t pbi_xstatus;
	uint32_t pbi_pid;
	uint32_t pbi_ppid;
	uint32_t pbi_uid;
	uint32_t pbi_gid;
	uint32_t pbi_ruid;
	uint32_t pbi_rgid;
	uint32_t pbi_svuid;
	uint32_t pbi_svgid;
	uint32_t rfu_1;
	char pbi_comm[16];
	char pbi_name[32];
	uint32_t pbi_nfiles;
	uint32_t pbi_pgid;
	uint32_t pbi_pjobc;
	uint32_t e_tdev;
	uint32_t e_tpgid;
	int32_t pbi_nice;
	uint64_t pbi_start_tvsec;
	uint64_t pbi_start_tvusec;
};

static int pidinfo(int32_t pid, uint32_t flavor, user_addr_t buffer,
		int32_t buffersize);
static int setcontrol(uint32_t flavor, user_addr_t buffer, int32_t buffersize);

int
sys_proc_info(int32_t callnum, int32_t pid, uint32_t flavor, uint64_t arg,
		user_addr_t buffer, int32_t buffersize)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "proc_info(%p, %p, %p, %p, %p, %p)\n", (void *)callnum,
			(void *)pid, (void *)flavor, (void *)arg,
			(void *)buffer, (void *)buffersize);
#endif
	switch (callnum) {
	case PROC_INFO_CALL_PIDINFO:
		return pidinfo(pid, flavor, buffer, buffersize);
	case PROC_INFO_CALL_SETCONTROL:
		return setcontrol(flavor, buffer, buffersize);
	case PROC_INFO_CALL_SET_DYLD_IMAGES:
		task_set_dyld_all_image_info(
				(mach_vm_address_t)buffer, buffersize);
		return 0;
	default:
		unimplemented();
	}
}

static int
pidinfo(int32_t pid, uint32_t flavor, user_addr_t buffer, int32_t buffersize)
{
	struct process process;
	if (process_lookup(pid, &process)) {
		return _ESRCH;
	}

	switch (flavor) {
	case PROC_PIDTBSDINFO: {
		struct proc_bsdinfo *info = buffer;
		if (buffersize < (int32_t)sizeof(*info)) {
			return _ENOMEM;
		}
		memset(info, 0, sizeof(*info));
		info->pbi_flags = PROC_FLAG_LP64;
		info->pbi_status = SRUN;
		info->pbi_pid = process.pid;
		info->pbi_ppid = process.ppid;
		info->pbi_uid = process.uid[1];
		info->pbi_gid = process.gid[1];
		info->pbi_ruid = process.uid[0];
		info->pbi_rgid = process.gid[0];
		info->pbi_svuid = process.uid[2];
		info->pbi_svgid = process.gid[2];
		memcpy(info->pbi_comm, process.comm, sizeof(process.comm));
		memcpy(info->pbi_name, process.comm, sizeof(process.comm));
		info->pbi_pgid = process.pgid;
		info->e_tpgid = process.tpgid;
		info->pbi_nice = process.nice;
		process_start_time(&process, &info->pbi_start_tvsec,
				&info->pbi_start_tvusec);
		return sizeof(*info);
	}
	case PROC_PIDT_SHORTBSDINFO: {
		struct proc_bsdshortinfo *info = buffer;
		if (buffersize < (int32_t)sizeof(*info)) {
			return _ENOMEM;
		}
		memset(info, 0, sizeof(*info));
		info->pbsi_pid = process.pid;
		info->pbsi_ppid = process.ppid;
		info->pbsi_pgid = process.pgid;
		info->pbsi_status = SRUN;
		memcpy(info->pbsi_comm, process.comm, sizeof(process.comm));
		info->pbsi_flags = PROC_FLAG_LP64;
		info->pbsi_uid = process.uid[1];
		info->pbsi_gid = process.gid[1];
		info->pbsi_ruid = process.uid[0];
		info->pbsi_rgid = process.gid[0];
		info->pbsi_svuid = process.uid[2];
		info->pbsi_svgid = process.gid[2];
		return sizeof(*info);
	}
	case PROC_PIDUNIQIDENTIFIERINFO: {
		struct proc_uniqidentifierinfo *info = buffer;
		if (buffersize < (int32_t)sizeof(*info)) {
			return _ENOMEM;
		}
		memset(info, 0, sizeof(*info));
		info->p_uniqueid = process.pid;
		info->p_puniqueid = process.ppid;
		return sizeof(*info);
	}
	default:
		unimplemented();
	}
}

static int
setcontrol(uint32_t flavor, user_addr_t buffer, int32_t buffersize)
{
	if (flavor != PROC_SELFSET_THREADNAME) {
		unimplemented();
	}

	char name[16];
	snprintf(name, sizeof(name), "%.*s", buffersize, (char *)buffer);
	prctl(PR_SET_NAME, name);
	return 0;
}
