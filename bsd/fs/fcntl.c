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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
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

#define _F_RDLCK 1
#define _F_UNLCK 2
#define _F_WRLCK 3

struct darwin_flock {
	int64_t l_start;
	int64_t l_len;
	int32_t l_pid;
	int16_t l_type;
	int16_t l_whence;
};

static int status_flags_to_darwin(int flags);
static int status_flags_from_darwin(int flags);
struct darwin_flocktimeout {
	struct darwin_flock fl;
	struct timespec timeout;
};

#define _F_ALLOCATECONTIG  0x2
#define _F_ALLOCATEALL     0x4
#define _F_ALLOCATEPERSIST 0x8
#define _F_PEOFPOSMODE     3
#define _F_VOLPOSMODE      4

struct darwin_fstore {
	uint32_t fst_flags;
	int32_t fst_posmode;
	int64_t fst_offset;
	int64_t fst_length;
	int64_t fst_bytesalloc;
};

struct darwin_fpunchhole {
	uint32_t fp_flags;
	uint32_t reserved;
	int64_t fp_offset;
	int64_t fp_length;
};

static int preallocate(int fd, struct darwin_fstore *store);
static int record_lock_timeout(
		int fd, int cmd, struct darwin_flocktimeout *lock);
static int record_lock(int fd, int cmd, struct darwin_flock *lock);
static short lock_type_from_darwin(short type);
static short lock_type_to_darwin(short type);

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
	case _F_BARRIERFSYNC:
		return errno_map(fsync(fd));
	case _F_GETLK:
		return record_lock(fd, F_GETLK, (void *)arg);
	case _F_SETLK:
		return record_lock(fd, F_SETLK, (void *)arg);
	case _F_SETLKW:
		return record_lock(fd, F_SETLKW, (void *)arg);
	case _F_OFD_GETLK:
		return record_lock(fd, F_OFD_GETLK, (void *)arg);
	case _F_OFD_SETLK:
		return record_lock(fd, F_OFD_SETLK, (void *)arg);
	case _F_OFD_SETLKW:
		return record_lock(fd, F_OFD_SETLKW, (void *)arg);
	case _F_SETLKWTIMEOUT:
		return record_lock_timeout(fd, F_SETLK, (void *)arg);
	case _F_OFD_SETLKWTIMEOUT:
		return record_lock_timeout(fd, F_OFD_SETLK, (void *)arg);
	case _F_SETCONFINED:
	case _F_RDADVISE:
	case _F_RDAHEAD:
	case _F_NOCACHE:
	case _F_SINGLE_WRITER:
	case _F_SETNOSIGPIPE:
		return 0;
	case _F_GETPROTECTIONCLASS:
		return _ENOTSUP;
	case _F_SETPROTECTIONCLASS:
		return 0;
	case _F_GETPATH: {
		char link[48], path[PATH_MAX];
		snprintf(link, sizeof(link), "/proc/thread-self/fd/%d", fd);
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
	/* Signatures are taken, as the code isn't checked against them */
	case _F_ADDSIGS:
	case _F_ADDFILESIGS:
	case _F_ADDFILESIGS_FOR_DYLD_SIM:
	case _F_ADDFILESUPPL:
		return 0;
	case _F_SPECULATIVE_READ:
		return 0;
	case _F_SETSTATICCONTENT:
		return 0;
	case _F_GETNOSIGPIPE:
		return 0;
	case _F_RECYCLE:
		return 0;
	case _F_FLUSH_DATA:
		return errno_map(fdatasync(fd));
	case _F_PREALLOCATE:
		return preallocate(fd, (void *)arg);
	case _F_PUNCHHOLE: {
		const struct darwin_fpunchhole *hole = (void *)arg;
		if (hole->fp_flags != 0) {
			return _EINVAL;
		}
		return errno_map(fallocate(fd,
				FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
				hole->fp_offset, hole->fp_length));
	}
	}

	unimplemented();
}

static int
preallocate(int fd, struct darwin_fstore *store)
{
	if (store->fst_flags
			& ~(_F_ALLOCATECONTIG | _F_ALLOCATEALL
					| _F_ALLOCATEPERSIST)) {
		return _EINVAL;
	}
	if (store->fst_length < 0) {
		return _EINVAL;
	}
	off_t start = store->fst_offset;
	if (store->fst_posmode == _F_PEOFPOSMODE) {
		struct stat s;
		if (fstat(fd, &s) == -1) {
			return err_map(errno);
		}
		start += (off_t)s.st_blocks * 512;
	} else if (store->fst_posmode != _F_VOLPOSMODE) {
		return _EINVAL;
	}
	store->fst_bytesalloc = 0;
	if (store->fst_length == 0) {
		return 0;
	}
	if (fallocate(fd, FALLOC_FL_KEEP_SIZE, start, store->fst_length)
			== -1) {
		return err_map(errno);
	}
	store->fst_bytesalloc = store->fst_length;
	return 0;
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

static int
record_lock_timeout(int fd, int cmd, struct darwin_flocktimeout *lock)
{
	struct timespec deadline;
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += lock->timeout.tv_sec;
	deadline.tv_nsec += lock->timeout.tv_nsec;
	if (deadline.tv_nsec >= 1000000000) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000;
	}

	while (true) {
		int result = record_lock(fd, cmd, &lock->fl);
		if (result != _EAGAIN && result != _EACCES) {
			return result;
		}
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec > deadline.tv_sec
				|| (now.tv_sec == deadline.tv_sec
						&& now.tv_nsec >= deadline.tv_nsec)) {
			return _ETIMEDOUT;
		}
		nanosleep(&(struct timespec){.tv_nsec = 1000000}, NULL);
	}
}

static int
record_lock(int fd, int cmd, struct darwin_flock *lock)
{
	struct flock host = {
			.l_type = lock_type_from_darwin(lock->l_type),
			.l_whence = lock->l_whence,
			.l_start = lock->l_start,
			.l_len = lock->l_len,
	};
	if (fcntl(fd, cmd, &host) == -1) {
		return err_map(errno);
	}
	if (cmd == F_GETLK || cmd == F_OFD_GETLK) {
		lock->l_type = lock_type_to_darwin(host.l_type);
		lock->l_whence = host.l_whence;
		lock->l_start = host.l_start;
		lock->l_len = host.l_len;
		lock->l_pid = host.l_pid;
	}
	return 0;
}

static short
lock_type_from_darwin(short type)
{
	switch (type) {
	case _F_RDLCK:
		return F_RDLCK;
	case _F_WRLCK:
		return F_WRLCK;
	default:
		return F_UNLCK;
	}
}

static short
lock_type_to_darwin(short type)
{
	switch (type) {
	case F_RDLCK:
		return _F_RDLCK;
	case F_WRLCK:
		return _F_WRLCK;
	default:
		return _F_UNLCK;
	}
}
