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

#include <signal.h>

#include "bsd/signo.h"
#include "check.h"

#define DARWIN_SIGBUS  10
#define DARWIN_SIGSYS  12
#define DARWIN_SIGCHLD 20
#define DARWIN_SIGINFO 29
#define DARWIN_SIGUSR1 30

int
main(void)
{
	CHECK(signo_to_linux(SIGSEGV) == SIGSEGV);
	CHECK(signo_to_linux(DARWIN_SIGBUS) == SIGBUS);
	CHECK(signo_to_linux(DARWIN_SIGSYS) == SIGSYS);
	CHECK(signo_to_linux(DARWIN_SIGCHLD) == SIGCHLD);
	CHECK(signo_to_linux(DARWIN_SIGUSR1) == SIGUSR1);
	CHECK(signo_to_linux(DARWIN_SIGINFO) == 0);
	CHECK(signo_to_linux(0) == 0);
	CHECK(signo_to_linux(64) == 0);

	for (int signo = 1; signo < 32; signo++) {
		int linux_signo = signo_to_linux(signo);
		if (linux_signo != 0) {
			CHECK(signo_from_linux(linux_signo) == signo);
		}
	}

	sigset_t set;
	sigset_to_linux((1U << (DARWIN_SIGUSR1 - 1)) | (1U << (SIGINT - 1))
					| (1U << (DARWIN_SIGINFO - 1)),
			&set);
	CHECK(sigismember(&set, SIGUSR1));
	CHECK(sigismember(&set, SIGINT));
	CHECK(!sigismember(&set, SIGUSR2));
	CHECK(!sigismember(&set, SIGPWR));

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGCHLD);
	sigaddset(&set, SIGPWR);
	CHECK(sigset_from_linux(&set)
			== ((1U << (DARWIN_SIGUSR1 - 1))
					| (1U << (DARWIN_SIGCHLD - 1))));
	return 0;
}
