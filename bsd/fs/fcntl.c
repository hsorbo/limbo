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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "bsd/xnu-errno.h"
#include "sysroot.h"

#define _F_DUPFD                    0
#define _F_GETFD                    1
#define _F_SETFD                    2
#define _F_GETFL                    3
#define _F_SETFL                    4
#define _F_GETOWN                   5
#define _F_SETOWN                   6
#define _F_GETLK                    7
#define _F_SETLK                    8
#define _F_SETLKW                   9
#define _F_SETLKWTIMEOUT            10
#define _F_FLUSH_DATA               40
#define _F_CHKCLEAN                 41
#define _F_PREALLOCATE              42
#define _F_SETSIZE                  43
#define _F_RDADVISE                 44
#define _F_RDAHEAD                  45
#define _F_NOCACHE                  48
#define _F_LOG2PHYS                 49
#define _F_GETPATH                  50
#define _F_FULLFSYNC                51
#define _F_PATHPKG_CHECK            52
#define _F_FREEZE_FS                53
#define _F_THAW_FS                  54
#define _F_GLOBAL_NOCACHE           55
#define _F_OPENFROM                 56
#define _F_UNLINKFROM               57
#define _F_CHECK_OPENEVT            58
#define _F_ADDSIGS                  59
#define _F_MARKDEPENDENCY           60
#define _F_ADDFILESIGS              61
#define _F_NODIRECT                 62
#define _F_GETPROTECTIONCLASS       63
#define _F_SETPROTECTIONCLASS       64
#define _F_LOG2PHYS_EXT             65
#define _F_GETLKPID                 66
#define _F_DUPFD_CLOEXEC            67
#define _F_SETSTATICCONTENT         68
#define _F_MOVEDATAEXTENTS          69
#define _F_SETBACKINGSTORE          70
#define _F_GETPATH_MTMINFO          71
#define _F_GETCODEDIR               72
#define _F_SETNOSIGPIPE             73
#define _F_GETNOSIGPIPE             74
#define _F_TRANSCODEKEY             75
#define _F_SINGLE_WRITER            76
#define _F_GETPROTECTIONLEVEL       77
#define _F_FINDSIGS                 78
#define _F_GETDEFAULTPROTLEVEL      79
#define _F_MAKECOMPRESSED           80
#define _F_SET_GREEDY_MODE          81
#define _F_SETIOTYPE                82
#define _F_ADDFILESIGS_FOR_DYLD_SIM 83
#define _F_RECYCLE                  84
#define _F_BARRIERFSYNC             85
#define _F_OFD_SETLK                90
#define _F_OFD_SETLKW               91
#define _F_OFD_GETLK                92
#define _F_OFD_SETLKWTIMEOUT        93
#define _F_OFD_GETLKPID             94
#define _F_SETCONFINED              95
#define _F_GETCONFINED              96
#define _F_ADDFILESIGS_RETURN       97
#define _F_CHECK_LV                 98
#define _F_PUNCHHOLE                99
#define _F_TRIM_ACTIVE_FILE         100
#define _F_SPECULATIVE_READ         101
#define _F_GETPATH_NOFIRMLINK       102
#define _F_ADDFILESIGS_INFO         103
#define _F_ADDFILESUPPL             104
#define _F_GETSIGSINFO              105

#define _MAXPATHLEN 1024

#define _O_NONBLOCK 0x00000004
#define _O_APPEND   0x00000008
#define _O_ASYNC    0x00000040
#define _O_FSYNC    0x00000080

static int status_flags_to_darwin(int flags);
static int status_flags_from_darwin(int flags);

int
sys_sys_fcntl(int fd, int cmd, long arg)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_fcntl(%p, %p, %p)\n", (void *)fd, (void *)cmd,
			(void *)arg);
#endif
	switch (cmd) {
	case _F_ADDFILESIGS_RETURN: {
		unsigned long *data = (void *)arg;
		data[0] = data[1];
		return 0;
	} break;
	case _F_DUPFD:
		return errno_map(fcntl(fd, F_DUPFD, arg));
	case _F_DUPFD_CLOEXEC:
		return errno_map(fcntl(fd, F_DUPFD_CLOEXEC, arg));
	case _F_GETFD:
		return errno_map(fcntl(fd, F_GETFD));
	case _F_SETFD:
		return errno_map(fcntl(fd, F_SETFD, arg & FD_CLOEXEC));
	case _F_GETFL: {
		int flags = fcntl(fd, F_GETFL);
		if (flags == -1) {
			return err_map(errno);
		}
		return status_flags_to_darwin(flags);
	}
	case _F_SETFL:
		return errno_map(fcntl(
				fd, F_SETFL, status_flags_from_darwin(arg)));
	case _F_FULLFSYNC:
		return errno_map(fsync(fd));
	case _F_NOCACHE:
	case _F_SETNOSIGPIPE:
		return 0;
	case _F_GETPROTECTIONCLASS:
		return _ENOTSUP;
	case _F_GETPATH: {
		char link[32], path[PATH_MAX];
		snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
		ssize_t length = readlink(link, path, sizeof(path) - 1);
		if (length == -1) {
			return err_map(errno);
		}
		path[length] = '\0';
		snprintf((char *)arg, _MAXPATHLEN, "%s",
				sysroot_guest_path(path));
		return 0;
	} break;
	case _F_CHECK_LV:
		return 0;
	case _F_SPECULATIVE_READ:
		return 0;
	}

	unimplemented();
}

static int
status_flags_to_darwin(int flags)
{
	int result = flags & O_ACCMODE;
	if (flags & O_NONBLOCK) {
		result |= _O_NONBLOCK;
	}
	if (flags & O_APPEND) {
		result |= _O_APPEND;
	}
	if (flags & O_ASYNC) {
		result |= _O_ASYNC;
	}
	if ((flags & O_SYNC) == O_SYNC) {
		result |= _O_FSYNC;
	}
	return result;
}

static int
status_flags_from_darwin(int flags)
{
	int result = 0;
	if (flags & _O_NONBLOCK) {
		result |= O_NONBLOCK;
	}
	if (flags & _O_APPEND) {
		result |= O_APPEND;
	}
	if (flags & _O_ASYNC) {
		result |= O_ASYNC;
	}
	return result;
}
