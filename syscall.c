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

#include <elf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <ucontext.h>

#include "bsd/handler.h"
#include "mdep/handler.h"
#include "osfmk/handler.h"
#include "syscall.h"

/* Never allow system calls from outside our binary region */
static const uint8_t selector = SYSCALL_DISPATCH_FILTER_BLOCK;

static void handle_syscall(int sig, siginfo_t *info, void *ucontext);

int
syscall_handler_install(void)
{
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	sigemptyset(&act.sa_mask);
	act.sa_sigaction = handle_syscall;
	act.sa_flags = SA_SIGINFO | SA_NODEFER;

	if (sigaction(SIGSYS, &act, NULL) == -1) {
		perror("sigaction");
		return 1;
	}
	return 0;
}

/*
 * System calls in Darwin are split into classes, as follows:
 * SYSCALL_CLASS_NONE  0   Invalid
 * SYSCALL_CLASS_MACH  1   Mach
 * SYSCALL_CLASS_UNIX  2   Unix/BSD
 * SYSCALL_CLASS_MDEP  3   Machine-dependent
 * SYSCALL_CLASS_DIAG  4   Diagnostics
 *
 * The system call number is the 24-bit left shift: (2 << 24) is to call
 * SYSCALL_CLASS_UNIX
 */

#define SYSCALL_CLASS_NONE 0
#define SYSCALL_CLASS_MACH (1 << 24)
#define SYSCALL_CLASS_UNIX (2 << 24)
#define SYSCALL_CLASS_MDEP (3 << 24)
#define SYSCALL_CLASS_DIAG (4 << 24)

static void
handle_syscall(int sig, siginfo_t *info, void *ucontext)
{
	ucontext_t *context = (ucontext_t *)ucontext;
	greg_t *regs = context->uc_mcontext.gregs;

	/*
	 * RDI, RSI, RDX, R10, R8, R9 and then spilling to the stack
	 *
	 * Presumably due to how the Linux system call trapping is implemented,
	 * the 7th argument lands on the 2nd slot of the stack (1st is LR)
	 *
	 * Returns in RAX
	 */

	uint64_t arg1 = regs[REG_RDI];
	uint64_t arg2 = regs[REG_RSI];
	uint64_t arg3 = regs[REG_RDX];
	uint64_t arg4 = regs[REG_R10];
	uint64_t arg5 = regs[REG_R8];
	uint64_t arg6 = regs[REG_R9];
	uint64_t *sp = (uint64_t *)regs[REG_RSP];

	/* Remove all status flags */
	regs[REG_EFL] = 0;

	unsigned long syscall = info->si_syscall;
	if (syscall >= SYSCALL_CLASS_MACH && syscall < SYSCALL_CLASS_UNIX) {
		regs[REG_RAX] = sys_osfmk(syscall - SYSCALL_CLASS_MACH, arg1,
				arg2, arg3, arg4, arg5, arg6, sp);
	} else if (syscall >= SYSCALL_CLASS_UNIX
			&& syscall < SYSCALL_CLASS_MDEP) {
		regs[REG_RAX] = sys_bsd(syscall - SYSCALL_CLASS_UNIX, arg1,
				arg2, arg3, arg4, arg5, arg6, sp);
	} else if (syscall >= SYSCALL_CLASS_MDEP
			&& syscall < SYSCALL_CLASS_DIAG) {
		regs[REG_RAX] = sys_mdep(syscall - SYSCALL_CLASS_MDEP, arg1,
				arg2, arg3, arg4, arg5, arg6, sp);
	} else {
#ifdef ENABLE_STRACE
		fprintf(stderr, ">> Missing system call: %#lx", syscall);
#endif
		abort();
	}
}

int
syscall_dispatch_enable(void)
{
	/* Enumerate the program headers of the executable to determine the
	 * region for which we should NOT trap all system calls */
	Elf64_Phdr *phdrs = (Elf64_Phdr *)getauxval(AT_PHDR);
	unsigned long e_phnum = getauxval(AT_PHNUM);

	for (uint32_t i = 0; i < e_phnum; i++) {
		Elf64_Phdr phdr = phdrs[i];
		if (phdr.p_type == PT_LOAD && phdr.p_flags & PF_X) {
			if (prctl(PR_SET_SYSCALL_USER_DISPATCH,
					    PR_SYS_DISPATCH_ON, phdr.p_vaddr,
					    phdr.p_memsz, &selector)) {
				perror("prctl");
				return 1;
			}
		}
	}
	return 0;
}
