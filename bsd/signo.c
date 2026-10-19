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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "signo.h"

#define DARWIN_NSIG 32

static const int linux_signals[DARWIN_NSIG] = {
		[1] = SIGHUP,
		[2] = SIGINT,
		[3] = SIGQUIT,
		[4] = SIGILL,
		[5] = SIGTRAP,
		[6] = SIGABRT,
		[8] = SIGFPE,
		[9] = SIGKILL,
		[10] = SIGBUS,
		[11] = SIGSEGV,
		[12] = SIGSYS,
		[13] = SIGPIPE,
		[14] = SIGALRM,
		[15] = SIGTERM,
		[16] = SIGURG,
		[17] = SIGSTOP,
		[18] = SIGTSTP,
		[19] = SIGCONT,
		[20] = SIGCHLD,
		[21] = SIGTTIN,
		[22] = SIGTTOU,
		[23] = SIGIO,
		[24] = SIGXCPU,
		[25] = SIGXFSZ,
		[26] = SIGVTALRM,
		[27] = SIGPROF,
		[28] = SIGWINCH,
		[30] = SIGUSR1,
		[31] = SIGUSR2,
};

int
signo_to_linux(int signo)
{
	return (signo > 0 && signo < DARWIN_NSIG) ? linux_signals[signo] : 0;
}

int
signo_from_linux(int signo)
{
	for (int i = 1; i < DARWIN_NSIG; i++) {
		if (linux_signals[i] == signo) {
			return i;
		}
	}
	return signo;
}

void
sigset_to_linux(uint32_t darwin_set, sigset_t *set)
{
	sigemptyset(set);
	for (int i = 1; i < DARWIN_NSIG; i++) {
		if ((darwin_set & (1U << (i - 1))) && linux_signals[i] != 0) {
			sigaddset(set, linux_signals[i]);
		}
	}
}

uint32_t
sigset_from_linux(const sigset_t *set)
{
	uint32_t result = 0;
	for (int i = 1; i < DARWIN_NSIG; i++) {
		if (linux_signals[i] != 0
				&& sigismember(set, linux_signals[i])) {
			result |= 1U << (i - 1);
		}
	}
	return result;
}
