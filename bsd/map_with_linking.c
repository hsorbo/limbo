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

#include <errno.h>
#include <mach-o/fixup-chains.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "handler.h"
#include "xnu-errno.h"

struct mwl_region {
	int mwlr_fd;
	vm_prot_t mwlr_protections;
	uint64_t mwlr_file_offset;
	mach_vm_address_t mwlr_address;
	mach_vm_size_t mwlr_size;
};

struct mwl_info_hdr {
	uint32_t mwli_version;
	uint16_t mwli_page_size;
	uint16_t mwli_pointer_format;
	uint32_t mwli_binds_offset;
	uint32_t mwli_binds_count;
	uint32_t mwli_chains_offset;
	uint32_t mwli_chains_size;
	uint64_t mwli_slide;
	uint64_t mwli_image_address;
};

static void apply_fixups(const struct mwl_region *regions,
		uint32_t region_count, const struct mwl_info_hdr *info);
static bool contains(const struct mwl_region *regions, uint32_t region_count,
		uint64_t address);
static void apply_chain(uint8_t *location, const struct mwl_info_hdr *info,
		const uint64_t *binds);

int
sys_map_with_linking_np(user_addr_t regions, uint32_t region_count,
		user_addr_t blob, uint32_t blob_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "map_with_linking_np(%p, %p, %p, %p)\n", regions,
			(void *)(uintptr_t)region_count, blob,
			(void *)(uintptr_t)blob_size);
#endif
	const struct mwl_region *r = regions;

	for (uint32_t i = 0; i < region_count; i++) {
		void *mapping = mmap((void *)r[i].mwlr_address, r[i].mwlr_size,
				PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED,
				r[i].mwlr_fd, r[i].mwlr_file_offset);
		if (mapping == MAP_FAILED) {
			return err_map(errno);
		}
	}

	apply_fixups(r, region_count, blob);

	for (uint32_t i = 0; i < region_count; i++) {
		if (mprotect((void *)r[i].mwlr_address, r[i].mwlr_size,
				    r[i].mwlr_protections & VM_PROT_ALL)
				== -1) {
			return err_map(errno);
		}
	}

	return 0;
}

static void
apply_fixups(const struct mwl_region *regions, uint32_t region_count,
		const struct mwl_info_hdr *info)
{
	const uint8_t *base = (const uint8_t *)info;
	const struct dyld_chained_starts_in_image *starts
			= (const void *)(base + info->mwli_chains_offset);
	const uint64_t *binds = (const void *)(base + info->mwli_binds_offset);

	for (uint32_t i = 0; i < starts->seg_count; i++) {
		if (starts->seg_info_offset[i] == 0) {
			continue;
		}

		const struct dyld_chained_starts_in_segment *segment
				= (const void *)((const uint8_t *)starts
						+ starts->seg_info_offset[i]);
		uint64_t segment_address = info->mwli_image_address
				+ segment->segment_offset;
		for (uint16_t page = 0; page < segment->page_count; page++) {
			uint16_t start = segment->page_start[page];
			uint64_t page_address = segment_address
					+ (uint64_t)page * segment->page_size;
			if (start == DYLD_CHAINED_PTR_START_NONE
					|| !contains(regions, region_count,
							page_address)) {
				continue;
			}
			apply_chain((uint8_t *)page_address + start, info,
					binds);
		}
	}
}

static bool
contains(const struct mwl_region *regions, uint32_t region_count,
		uint64_t address)
{
	for (uint32_t i = 0; i < region_count; i++) {
		if (address >= regions[i].mwlr_address
				&& address < regions[i].mwlr_address
								+ regions[i].mwlr_size) {
			return true;
		}
	}
	return false;
}

static void
apply_chain(uint8_t *location, const struct mwl_info_hdr *info,
		const uint64_t *binds)
{
	while (true) {
		union {
			uint64_t raw;
			struct dyld_chained_ptr_64_rebase rebase;
			struct dyld_chained_ptr_64_bind bind;
		} fixup;
		memcpy(&fixup.raw, location, sizeof(fixup.raw));

		uint64_t value;
		if (fixup.bind.bind) {
			value = binds[fixup.bind.ordinal] + fixup.bind.addend;
		} else {
			uint64_t target = fixup.rebase.target;
			if (info->mwli_pointer_format
					== DYLD_CHAINED_PTR_64_OFFSET) {
				target += info->mwli_image_address;
			} else {
				target += info->mwli_slide;
			}
			value = target | ((uint64_t)fixup.rebase.high8 << 56);
		}
		memcpy(location, &value, sizeof(value));

		if (fixup.rebase.next == 0) {
			break;
		}
		location += fixup.rebase.next * 4;
	}
}
