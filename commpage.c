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

#include <stdio.h>
#include <sys/mman.h>
#include <time.h>
#include <x86intrin.h>

#include "commpage.h"

static void init_nanotime(void);
static uint64_t sample_clocks(uint64_t *tsc);

int
commpage_mmap(void)
{
	void *commpage = mmap((void *)_COMM_PAGE_START_ADDRESS,
			_COMM_PAGE_AREA_LENGTH, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0);
	if (commpage == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	/* TODO: Initialize the entire commpage */
	*(uint16_t *)_COMM_PAGE_VERSION = _COMM_PAGE_THIS_VERSION;
	*(uint8_t *)_COMM_PAGE_ACTIVE_CPUS = 12;
	*(uint8_t *)_COMM_PAGE_LOGICAL_CPUS = 24;
	*(uint8_t *)_COMM_PAGE_PHYSICAL_CPUS = 12;
	*(uint8_t *)_COMM_PAGE_USER_PAGE_SHIFT_64 = 12;
	*(uint64_t *)_COMM_PAGE_MEMORY_SIZE = 17179869184;
	init_nanotime();

	return 0;
}

uint64_t
commpage_absolute_time(void)
{
	uint64_t elapsed = __rdtsc() - *(uint64_t *)_COMM_PAGE_NT_TSC_BASE;
	return ((unsigned __int128)elapsed * *(uint32_t *)_COMM_PAGE_NT_SCALE
			       >> 32)
			+ *(uint64_t *)_COMM_PAGE_NT_NS_BASE;
}

static void
init_nanotime(void)
{
	uint64_t start_tsc, end_tsc;
	uint64_t start_ns = sample_clocks(&start_tsc);
	nanosleep(&(struct timespec){.tv_nsec = 1000000}, NULL);
	uint64_t end_ns = sample_clocks(&end_tsc);

	*(uint64_t *)_COMM_PAGE_NT_TSC_BASE = start_tsc;
	*(uint32_t *)_COMM_PAGE_NT_SCALE
			= ((unsigned __int128)(end_ns - start_ns) << 32)
			/ (end_tsc - start_tsc);
	*(uint32_t *)_COMM_PAGE_NT_SHIFT = 0;
	*(uint64_t *)_COMM_PAGE_NT_NS_BASE = start_ns;
	*(uint32_t *)_COMM_PAGE_NT_GENERATION = 1;
}

static uint64_t
sample_clocks(uint64_t *tsc)
{
	struct timespec now;
	uint64_t before = __rdtsc();
	clock_gettime(CLOCK_MONOTONIC, &now);
	uint64_t after = __rdtsc();

	*tsc = before + (after - before) / 2;
	return now.tv_sec * 1000000000ULL + now.tv_nsec;
}
