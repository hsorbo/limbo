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

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/machine.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

#include "shared_cache.h"
#include "sysroot.h"

void *shared_cache_start = NULL;
int shared_cache_cpu_subtype = CPU_SUBTYPE_X86_64_ALL;

static int reserve_shared_region(dyld_cache_header_t *header);
static int map_cache_file(int f, dyld_cache_header_t *header);
static int map_cache_mapping(int f, dyld_cache_mapping_and_slide_info_t *m);
static int map_subcaches(int f, const char *path, dyld_cache_header_t *header);
static int map_subcache(const char *path, dyld_subcache_entry_t *entry);
static int map_dynamic_data(
		int f, const char *path, dyld_cache_header_t *header);
static void rebase_chain(uint8_t *page_content, uint16_t page_start_offset,
		dyld_cache_slide_info2_t *info);
static void rebase_page(dyld_cache_slide_info2_t *info, uint64_t address);

int
shared_cache_mmap(void)
{
	char buffer[PATH_MAX];
	const char *path = "/System/Library/dyld/dyld_shared_cache_x86_64";
	const char *host_path = sysroot_host_path(path, 0, buffer);
	if (access(host_path, F_OK) != 0) {
		path = "/System/Library/dyld/dyld_shared_cache_x86_64h";
		host_path = sysroot_host_path(path, 0, buffer);
		shared_cache_cpu_subtype = CPU_SUBTYPE_X86_64_H;
	}

	int f = open(host_path, O_RDONLY);
	if (f == -1) {
		perror("open");
		return 1;
	}

	dyld_cache_header_t header;
	if (pread(f, &header, sizeof(header), 0) != sizeof(header)) {
		perror("pread");
		goto error;
	}

	if (reserve_shared_region(&header) || map_cache_file(f, &header)
			|| map_subcaches(f, host_path, &header)
			|| map_dynamic_data(f, path, &header)) {
		goto error;
	}

	close(f);
	shared_cache_start = (void *)header.sharedRegionStart;
	return 0;
error:
	close(f);
	return 1;
}

static int
reserve_shared_region(dyld_cache_header_t *header)
{
	void *region = mmap((void *)header->sharedRegionStart,
			header->sharedRegionSize, PROT_NONE,
			MAP_PRIVATE | MAP_ANON | MAP_FIXED_NOREPLACE
					| MAP_NORESERVE,
			-1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	return 0;
}

static int
map_cache_file(int f, dyld_cache_header_t *header)
{
	uint32_t count = header->mappingWithSlideCount;
	dyld_cache_mapping_and_slide_info_t mappings[count];
	ssize_t size = sizeof(mappings);
	if (pread(f, mappings, size, header->mappingWithSlideOffset) != size) {
		perror("pread");
		return 1;
	}

	for (uint32_t i = 0; i < count; i++) {
		if (map_cache_mapping(f, &mappings[i])) {
			return 1;
		}
	}
	return 0;
}

static int
map_cache_mapping(int f, dyld_cache_mapping_and_slide_info_t *m)
{
	if (m->slideInfoFileSize == 0) {
		void *base = mmap((void *)m->address, m->size, m->initProt,
				MAP_PRIVATE | MAP_FIXED, f, m->fileOffset);
		if (base == MAP_FAILED) {
			perror("mmap");
			return 1;
		}
		return 0;
	}

	void *base = mmap((void *)m->address, m->size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_FIXED, f, m->fileOffset);
	if (base == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	dyld_cache_slide_info2_t *info = malloc(m->slideInfoFileSize);
	ssize_t size = m->slideInfoFileSize;
	if (pread(f, info, size, m->slideInfoFileOffset) != size) {
		perror("pread");
		free(info);
		return 1;
	}

	assert(info->version == 2);
	assert(info->page_size == 0x1000);
	assert(info->delta_mask == 0x00ffff0000000000);
	assert(info->page_starts_count == m->size / info->page_size);
	rebase_page(info, m->address);
	free(info);

	if (mprotect(base, m->size, m->initProt) == -1) {
		perror("mprotect");
		return 1;
	}
	return 0;
}

static int
map_subcaches(int f, const char *path, dyld_cache_header_t *header)
{
	if (header->mappingOffset
			<= offsetof(dyld_cache_header_t, subCacheArrayCount)) {
		return 0;
	}

	uint32_t count = header->subCacheArrayCount;
	dyld_subcache_entry_t entries[count];
	ssize_t size = sizeof(entries);
	if (pread(f, entries, size, header->subCacheArrayOffset) != size) {
		perror("pread");
		return 1;
	}

	for (uint32_t i = 0; i < count; i++) {
		if (map_subcache(path, &entries[i])) {
			return 1;
		}
	}
	return 0;
}

static int
map_subcache(const char *path, dyld_subcache_entry_t *entry)
{
	char subcache_path[PATH_MAX];
	snprintf(subcache_path, sizeof(subcache_path), "%s%s", path,
			entry->fileSuffix);

	int f = open(subcache_path, O_RDONLY);
	if (f == -1) {
		perror("open");
		return 1;
	}

	dyld_cache_header_t header;
	int result = 1;
	if (pread(f, &header, sizeof(header), 0) != sizeof(header)) {
		perror("pread");
	} else {
		result = map_cache_file(f, &header);
	}

	close(f);
	return result;
}

static int
map_dynamic_data(int f, const char *path, dyld_cache_header_t *header)
{
	if (header->mappingOffset
			<= offsetof(dyld_cache_header_t, dynamicDataMaxSize)) {
		return 0;
	}

	struct statfs fs;
	struct stat st;
	if (fstatfs(f, &fs) == -1 || fstat(f, &st) == -1) {
		perror("stat");
		return 1;
	}

	dyld_cache_dynamic_data_header_t *data = mmap(
			(void *)(header->sharedRegionStart
					+ header->dynamicDataOffset),
			header->dynamicDataMaxSize, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
	if (data == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	strcpy(data->magic, "dyld_data    v4");
	memcpy(&data->fsId, &fs.f_fsid, sizeof(data->fsId));
	data->fsObjId = st.st_ino;
	data->cachePathOffset
			= offsetof(dyld_cache_dynamic_data_header_t, strings);
	data->cachePathSize = strlen(path) + 1;
	memcpy(data->strings, path, data->cachePathSize);

	if (mprotect(data, header->dynamicDataMaxSize, PROT_READ) == -1) {
		perror("mprotect");
		return 1;
	}
	return 0;
}

/*
 * For details on how sliding the dyld cache works, see dyld_cache_slide_info2
 * in dyld_cache_format.h
 */
static void
rebase_page(dyld_cache_slide_info2_t *info, uint64_t address)
{
	uint16_t *page_starts = (uint16_t *)((uintptr_t)info
			+ info->page_starts_offset);
	uint16_t *page_extras = (uint16_t *)((uintptr_t)info
			+ info->page_extras_offset);

	for (uint32_t j = 0; j < info->page_starts_count; j++) {
		uint8_t *page_content
				= (uint8_t *)(address + j * info->page_size);
		uint16_t page_entry = page_starts[j];
		uint16_t page_start_offset = page_entry << 2;

		if (page_entry == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE) {
			continue;
		}

		if (page_entry & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) {
			/* Multiple linked-lists are needed to rebase */
			uint16_t chain_index = page_entry & 0x3fff;
			uint16_t extra;

			/* High-level algorithm described in dyld_cache_format.h
			 */
			do {
				uint16_t page_start_offset;

				assert(chain_index < info->page_extras_count);

				extra = page_extras[chain_index];
				page_start_offset = (uint16_t)(
						(extra & 0x3fff) << 2);

				rebase_chain(page_content, page_start_offset,
						info);

				chain_index++;
			} while (!(extra & DYLD_CACHE_SLIDE_PAGE_ATTR_END));
		} else {
			/* Standalone linked-list provides rebase details */
			rebase_chain(page_content, page_start_offset, info);
		}
	}
}

static void
rebase_chain(uint8_t *page_content, uint16_t page_offset,
		dyld_cache_slide_info2_t *info)
{
	uint32_t last_page_offset = info->page_size - sizeof(uint64_t);

	uint64_t delta_mask = info->delta_mask;
	uint64_t value_mask = ~delta_mask;
	uint64_t value_add = info->value_add;
	uint64_t delta_shift = __builtin_ctzll(delta_mask) - 2;

	uint32_t delta;
	for (delta = 1; delta != 0 && page_offset <= last_page_offset;
			page_offset += delta) {
		uint8_t *l = page_content + page_offset;

		uint64_t value;
		memcpy(&value, l, sizeof(value));

		delta = (uint32_t)((value & delta_mask) >> delta_shift);
		value &= value_mask;

		if (value != 0) {
			value += value_add;
			/* No need to add slide, we don't rebase it */
		}

		memcpy(l, &value, sizeof(value));
	}
}
