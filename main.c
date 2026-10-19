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

#include <asm/prctl.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/random.h>
#include <unistd.h>

#include "commpage.h"
#include "linker.h"
#include "shared_cache.h"
#include "syscall.h"
#include "sysroot.h"

/* Temporary TLS for dyld */
static char dyld_ls[0x1000];

int arch_prctl(int, unsigned long);

static int run(int argc, char *argv[], char *envp[]);
static uintptr_t build_stack(uint8_t *exe_base, const char *path, int argc,
		char *argv[], char *envp[]);
static int restart_without_aslr(char *argv[], char *envp[]);

int
main(int argc, char *argv[], char *envp[])
{
	if (!(personality(0xffffffff) & ADDR_NO_RANDOMIZE)) {
		return restart_without_aslr(argv, envp);
	}

	if (syscall_dispatch_enable()) {
		return 1;
	}

	return run(argc, argv, envp);
}

static int
restart_without_aslr(char *argv[], char *envp[])
{
	if (personality(personality(0xffffffff) | ADDR_NO_RANDOMIZE) == -1) {
		perror("personality");
		return 1;
	}

	execve("/proc/self/exe", argv, envp);
	perror("execve");
	return 1;
}

static int
run(int argc, char *argv[], char *envp[])
{
	if (argc < 3) {
		fprintf(stderr, "limbo: no path\n");
		return 1;
	}

	if (sysroot_open() || syscall_handler_install()) {
		goto error;
	}

	/* Map the shared cache into our memory space, persisted across fork()
	 */
	if (shared_cache_mmap(
			    "/System/Library/dyld/dyld_shared_cache_x86_64")) {
		fprintf(stderr,
				"limbo: could not map and rebase shared "
				"cache\n");
		return 1;
	}

	/* Map the target executable and determine its interpreter */
	const char *dylinker_path = NULL;
	uint8_t *exe_base = linker_link(argv[1], &dylinker_path, NULL);
	if (exe_base == NULL || dylinker_path == NULL) {
		fprintf(stderr, "limbo: failed to load binary\n");
		return 1;
	}

	/* Map the target executable's interpreter (dyld) */
	char dylinker_host_path[PATH_MAX];
	uintptr_t entry = 0;
	uint8_t *dyld_base = linker_link(
			sysroot_host_path(dylinker_path, 0, dylinker_host_path),
			NULL, &entry);
	if (dyld_base == NULL || entry == 0) {
		fprintf(stderr,
				"limbo: failed to load binary "
				"interpreter\n");
		return 1;
	}

	/* Set up the stack in the way that dyld expects */
	uintptr_t stack_base = build_stack(
			exe_base, argv[1], argc - 2, argv + 2, envp);
	if (stack_base == 0) {
		goto error;
	}

	if (commpage_mmap()) {
		goto error;
	}

	/* Set up the temporary zero-ed TLS storage for dyld */
	memset(dyld_ls, 0, sizeof(dyld_ls));
	arch_prctl(ARCH_SET_GS, (unsigned long)dyld_ls);

	asm volatile("mov %0, %%rsp; jmp *%1" ::"r"(stack_base), "r"(entry));
	__builtin_unreachable();
error:
	exit(1);
}

static uintptr_t
build_stack(uint8_t *exe_base, const char *path, int argc, char *argv[],
		char *envp[])
{
	/* Map 64mb of stack with  MAP_GROWSDOWN so that the stack automatically
	 * grows down */
	void *stack = mmap(
			(void *)((uintptr_t)VM_USRSTACK64 - 64 * 1024 * 1024),
			64 * 1024 * 1024, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_FIXED | MAP_ANON | MAP_GROWSDOWN, -1,
			0);
	if (stack == MAP_FAILED) {
		perror("mmap");
		return 0;
	}

	uint64_t entropy[4];
	if (getrandom(entropy, sizeof(entropy), 0) != sizeof(entropy)) {
		perror("getrandom");
		return 0;
	}

	char *apple[4];
	uint32_t applec = sizeof(apple) / sizeof(apple[0]);
	asprintf(&apple[0], "executable_path=%s", sysroot_guest_path(path));
	asprintf(&apple[1], "stack_guard=0x%lx", entropy[0]);
	asprintf(&apple[2], "malloc_entropy=0x%lx,0x%lx", entropy[1],
			entropy[2]);
	asprintf(&apple[3], "ptr_munge=0x%lx", entropy[3]);

	uint32_t envc;
	for (envc = 0; envp[envc] != NULL; envc++)
		;

	uintptr_t stack_base = (uintptr_t)VM_USRSTACK64;
	stack_base -= (applec + 1) * sizeof(void *); /* Apple env pointers */
	stack_base -= (envc + 1) * sizeof(void *);   /* Env pointers */
	stack_base -= (argc + 1) * sizeof(void *);   /* Arg pointers */
	stack_base -= sizeof(long) * 2;              /* Main frame */
	stack_base = (stack_base & ~0xf);

	unsigned long *sp = (unsigned long *)stack_base;
	/* Main frame */
	*sp++ = (unsigned long)exe_base;
	*sp++ = (unsigned long)argc;

	/* Arguments */
	for (int i = 0; i < argc; i++) {
		*sp++ = (unsigned long)argv[i];
	}
	*sp++ = 0; /* End of arguments */

	/* Environment */
	for (uint32_t i = 0; i < envc; i++) {
		*sp++ = (unsigned long)envp[i];
	}
	*sp++ = 0; /* End of environment */

	/* Apple environment */
	for (uint32_t i = 0; i < applec; i++) {
		*sp++ = (unsigned long)apple[i];
	}
	*sp++ = 0; /* End of environment */

	return stack_base;
}
