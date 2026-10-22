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

#include <errno.h>
#include <mach/mach_types.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "ipc.h"
#include "mach_vm.h"

struct memory_entry {
	int fd;
	mach_vm_size_t size;
};

#define VM_FLAGS_ANYWHERE  0x0001
#define VM_FLAGS_OVERWRITE 0x4000
#define LOW_ANYWHERE_BASE  0x100000000

static kern_return_t map_anonymous(mach_vm_address_t *address,
		mach_vm_size_t size, mach_vm_offset_t mask, int flags,
		vm_prot_t protection);
static void *map_aligned(mach_vm_size_t size, mach_vm_offset_t mask,
		vm_prot_t protection);
static kern_return_t remap_copy(mach_vm_address_t *target_address,
		mach_vm_size_t size, mach_vm_offset_t mask, int flags,
		mach_vm_address_t src_address, vm_prot_t *protection);
static vm_prot_t region_protection(mach_vm_address_t address);
static kern_return_t map_entry(mach_vm_address_t *address, mach_vm_size_t size,
		mach_vm_offset_t mask, int flags,
		const struct memory_entry *entry, memory_object_offset_t offset,
		boolean_t copy, vm_prot_t protection);

kern_return_t
_kernelrpc_mach_vm_allocate(vm_task_entry_t target, mach_vm_address_t *address,
		mach_vm_size_t size, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_vm_allocate(%p, %p, %p, %p)\n",
			(void *)target, (void *)address, (void *)size,
			(void *)flags);
#endif
	return map_anonymous(address, size, 0, flags, VM_PROT_DEFAULT);
}

static kern_return_t
map_anonymous(mach_vm_address_t *address, mach_vm_size_t size,
		mach_vm_offset_t mask, int flags, vm_prot_t protection)
{
	size = (size + PAGE_MASK) & ~PAGE_MASK;

	void *base;
	if (flags & VM_FLAGS_ANYWHERE) {
		base = map_aligned(size, mask | PAGE_MASK, protection);
	} else {
		int placement = (flags & VM_FLAGS_OVERWRITE)
				? MAP_FIXED
				: MAP_FIXED_NOREPLACE;
		base = mmap((void *)*address, size, protection,
				MAP_PRIVATE | MAP_ANON | placement, -1, 0);
	}
	if (base == MAP_FAILED) {
		return KERN_NO_SPACE;
	}

	*address = (mach_vm_address_t)base;
	return KERN_SUCCESS;
}

static void *
map_aligned(mach_vm_size_t size, mach_vm_offset_t mask, vm_prot_t protection)
{
	mach_vm_size_t padded_size = size + mask + 1;
#ifdef __x86_64__
	uint8_t *padded = mmap(NULL, padded_size, protection,
			MAP_PRIVATE | MAP_ANON, -1, 0);
	if (padded == MAP_FAILED) {
		return MAP_FAILED;
	}
#else
	static uintptr_t bump = LOW_ANYWHERE_BASE;
	uint8_t *padded;
	while (true) {
		padded = mmap((void *)bump, padded_size, protection,
				MAP_PRIVATE | MAP_ANON | MAP_FIXED_NOREPLACE,
				-1, 0);
		bump += (padded_size + PAGE_MASK) & ~(uintptr_t)PAGE_MASK;
		if (padded != MAP_FAILED) {
			break;
		}
		if (errno != EEXIST) {
			return MAP_FAILED;
		}
	}
#endif

	uint8_t *base = (uint8_t *)(((uintptr_t)padded + mask) & ~mask);
	uint8_t *end = base + size;
	uint8_t *padded_end = padded + padded_size;
	if (base != padded) {
		munmap(padded, base - padded);
	}
	if (end != padded_end) {
		munmap(end, padded_end - end);
	}
	return base;
}

kern_return_t
_kernelrpc_mach_vm_deallocate(vm_task_entry_t target, mach_vm_address_t address,
		mach_vm_size_t size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_vm_deallocate(%p, %p, %p)\n",
			(void *)target, (void *)address, (void *)size);
#endif
	mach_vm_address_t start = address & ~PAGE_MASK;
	mach_vm_address_t end = (address + size + PAGE_MASK) & ~PAGE_MASK;
	if (start != end && munmap((void *)start, end - start) == -1) {
		return KERN_INVALID_ADDRESS;
	}
	return KERN_SUCCESS;
}

kern_return_t
_kernelrpc_mach_vm_protect(vm_task_entry_t target_task,
		mach_vm_address_t address, mach_vm_size_t size,
		boolean_t set_maximum, vm_prot_t new_protection)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_vm_protect(%p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)size,
			(void *)set_maximum, (void *)new_protection);
#endif
	if (set_maximum) {
		return KERN_SUCCESS;
	}

	mach_vm_address_t start = address & ~PAGE_MASK;
	mach_vm_address_t end = (address + size + PAGE_MASK) & ~PAGE_MASK;
	if (mprotect((void *)start, end - start, new_protection & VM_PROT_ALL)
			== -1) {
		return KERN_PROTECTION_FAILURE;
	}
	return KERN_SUCCESS;
}

kern_return_t
mach_vm_inherit(vm_task_entry_t target_task, mach_vm_address_t address,
		mach_vm_size_t size, vm_inherit_t new_inheritance)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_inherit(%p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)size,
			(void *)new_inheritance);
#endif
	unimplemented();
}

kern_return_t
_kernelrpc_mach_vm_read(vm_map_read_t target_task, mach_vm_address_t address,
		mach_vm_size_t size, vm_offset_t *data,
		mach_msg_type_number_t *dataCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_vm_read(%p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)size,
			(void *)data, (void *)dataCnt);
#endif
	unimplemented();
}

kern_return_t
mach_vm_read_list(vm_map_read_t target_task, mach_vm_read_entry_t data_list,
		natural_t count)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_read_list(%p, %p, %p)\n", (void *)target_task,
			(void *)data_list, (void *)count);
#endif
	unimplemented();
}

kern_return_t
mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data,
		mach_msg_type_number_t dataCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_write(%p, %p, %p, %p)\n", (void *)target_task,
			(void *)address, (void *)data, (void *)dataCnt);
#endif
	memmove((void *)address, (void *)data, dataCnt);
	return KERN_SUCCESS;
}

kern_return_t
mach_vm_copy(vm_map_t target_task, mach_vm_address_t source_address,
		mach_vm_size_t size, mach_vm_address_t dest_address)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_copy(%p, %p, %p, %p)\n", (void *)target_task,
			(void *)source_address, (void *)size,
			(void *)dest_address);
#endif
	memmove((void *)dest_address, (void *)source_address, size);
	return KERN_SUCCESS;
}

kern_return_t
mach_vm_read_overwrite(vm_map_read_t target_task, mach_vm_address_t address,
		mach_vm_size_t size, mach_vm_address_t data,
		mach_vm_size_t *outsize)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_read_overwrite(%p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)size,
			(void *)data, (void *)outsize);
#endif
	memmove((void *)data, (void *)address, size);
	*outsize = size;
	return KERN_SUCCESS;
}

kern_return_t
mach_vm_msync(vm_map_t target_task, mach_vm_address_t address,
		mach_vm_size_t size, vm_sync_t sync_flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_msync(%p, %p, %p, %p)\n", (void *)target_task,
			(void *)address, (void *)size, (void *)sync_flags);
#endif
	unimplemented();
}

kern_return_t
mach_vm_behavior_set(vm_map_t target_task, mach_vm_address_t address,
		mach_vm_size_t size, vm_behavior_t new_behavior)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_behavior_set(%p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)size,
			(void *)new_behavior);
#endif
	unimplemented();
}

kern_return_t
_kernelrpc_mach_vm_map(vm_task_entry_t target_task, mach_vm_address_t *address,
		mach_vm_size_t size, mach_vm_offset_t mask, int flags,
		mem_entry_name_port_t object, memory_object_offset_t offset,
		boolean_t copy, vm_prot_t cur_protection,
		vm_prot_t max_protection, vm_inherit_t inheritance)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"_kernelrpc_mach_vm_map(%p, %p, %p, %p, %p, %p, %p, "
			"%p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)size,
			(void *)mask, (void *)flags, (void *)object,
			(void *)offset, (void *)copy, (void *)cur_protection,
			(void *)max_protection, (void *)inheritance);
#endif
	if (object != MACH_PORT_NULL) {
		struct memory_entry *entry = ipc_kobject_lookup(
				object, IPC_KOBJECT_MEMORY_ENTRY);
		if (entry == NULL) {
			unimplemented();
		}
		return map_entry(address, size, mask, flags, entry, offset,
				copy, cur_protection);
	}

	return map_anonymous(address, size, mask, flags, cur_protection);
}

static kern_return_t
map_entry(mach_vm_address_t *address, mach_vm_size_t size,
		mach_vm_offset_t mask, int flags,
		const struct memory_entry *entry, memory_object_offset_t offset,
		boolean_t copy, vm_prot_t protection)
{
	size = (size + PAGE_MASK) & ~PAGE_MASK;
	if (offset + size > entry->size) {
		return KERN_INVALID_ARGUMENT;
	}

	kern_return_t kr = map_anonymous(
			address, size, mask, flags, VM_PROT_NONE);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	void *base = mmap((void *)*address, size, protection,
			(copy ? MAP_PRIVATE : MAP_SHARED) | MAP_FIXED,
			entry->fd, offset);
	if (base == MAP_FAILED) {
		munmap((void *)*address, size);
		return KERN_NO_SPACE;
	}
	return KERN_SUCCESS;
}

kern_return_t
mach_vm_machine_attribute(vm_map_t target_task, mach_vm_address_t address,
		mach_vm_size_t size, vm_machine_attribute_t attribute,
		vm_machine_attribute_val_t *value)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_machine_attribute(%p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)size,
			(void *)attribute, (void *)value);
#endif
	unimplemented();
}

kern_return_t
_kernelrpc_mach_vm_remap(vm_map_t target_task,
		mach_vm_address_t *target_address, mach_vm_size_t size,
		mach_vm_offset_t mask, int flags, vm_map_t src_task,
		mach_vm_address_t src_address, boolean_t copy,
		vm_prot_t *cur_protection, vm_prot_t *max_protection,
		vm_inherit_t inheritance)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"_kernelrpc_mach_vm_remap(%p, %p, %p, %p, %p, %p, %p, "
			"%p, %p, %p, %p)\n",
			(void *)target_task, (void *)target_address,
			(void *)size, (void *)mask, (void *)flags,
			(void *)src_task, (void *)src_address, (void *)copy,
			(void *)cur_protection, (void *)max_protection,
			(void *)inheritance);
#endif
	if (!copy) {
		unimplemented();
	}

	*cur_protection = region_protection(src_address);
	*max_protection = VM_PROT_ALL;
	return remap_copy(target_address, size, mask, flags, src_address,
			cur_protection);
}

static kern_return_t
remap_copy(mach_vm_address_t *target_address, mach_vm_size_t size,
		mach_vm_offset_t mask, int flags, mach_vm_address_t src_address,
		vm_prot_t *protection)
{
	kern_return_t kr = map_anonymous(target_address, size, mask, flags,
			VM_PROT_READ | VM_PROT_WRITE);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	memcpy((void *)*target_address, (void *)src_address, size);
	mprotect((void *)*target_address, size, *protection);
	return KERN_SUCCESS;
}

static vm_prot_t
region_protection(mach_vm_address_t address)
{
	FILE *maps = fopen("/proc/self/maps", "r");
	char line[512];
	vm_prot_t protection = VM_PROT_NONE;
	while (fgets(line, sizeof(line), maps) != NULL) {
		unsigned long start, end;
		char perms[5];
		if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3
				&& address >= start && address < end) {
			protection = ((perms[0] == 'r') ? VM_PROT_READ : 0)
					| ((perms[1] == 'w') ? VM_PROT_WRITE
							     : 0)
					| ((perms[2] == 'x') ? VM_PROT_EXECUTE
							     : 0);
			break;
		}
	}
	fclose(maps);
	return protection;
}

kern_return_t
mach_vm_page_query(vm_map_read_t target_map, mach_vm_offset_t offset,
		integer_t *disposition, integer_t *ref_count)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_page_query(%p, %p, %p, %p)\n",
			(void *)target_map, (void *)offset, (void *)disposition,
			(void *)ref_count);
#endif
	unimplemented();
}

kern_return_t
mach_vm_region_recurse(vm_map_read_t target_task, mach_vm_address_t *address,
		mach_vm_size_t *size, natural_t *nesting_depth,
		vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_region_recurse(%p, %p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)size,
			(void *)nesting_depth, (void *)info, (void *)infoCnt);
#endif
	unimplemented();
}

kern_return_t
mach_vm_region(vm_map_read_t target_task, mach_vm_address_t *address,
		mach_vm_size_t *size, vm_region_flavor_t flavor,
		vm_region_info_t info, mach_msg_type_number_t *infoCnt,
		mach_port_t *object_name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_region(%p, %p, %p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)size,
			(void *)flavor, (void *)info, (void *)infoCnt,
			(void *)object_name);
#endif
	unimplemented();
}

kern_return_t
mach_make_memory_entry(vm_map_t target_task, memory_object_size_t *size,
		memory_object_offset_t offset, vm_prot_t permission,
		mach_port_t *object_handle, mem_entry_name_port_t parent_handle)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_make_memory_entry(%p, %p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)size, (void *)offset,
			(void *)permission, (void *)object_handle,
			(void *)parent_handle);
#endif
	unimplemented();
}

kern_return_t
_kernelrpc_mach_vm_purgable_control(vm_map_t target_task,
		mach_vm_address_t address, vm_purgable_t control, int *state)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_vm_purgable_control(%p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)control,
			(void *)state);
#endif
	unimplemented();
}

kern_return_t
mach_vm_page_info(vm_map_read_t target_task, mach_vm_address_t address,
		vm_page_info_flavor_t flavor, vm_page_info_t info,
		mach_msg_type_number_t *infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_page_info(%p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)address, (void *)flavor,
			(void *)info, (void *)infoCnt);
#endif
	unimplemented();
}

kern_return_t
mach_vm_page_range_query(vm_map_read_t target_map, mach_vm_offset_t address,
		mach_vm_size_t size, mach_vm_address_t dispositions,
		mach_vm_size_t *dispositions_count)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_page_range_query(%p, %p, %p, %p, %p)\n",
			(void *)target_map, (void *)address, (void *)size,
			(void *)dispositions, (void *)dispositions_count);
#endif
	unimplemented();
}

kern_return_t
_kernelrpc_mach_vm_remap_new(vm_map_t target_task,
		mach_vm_address_t *target_address, mach_vm_size_t size,
		mach_vm_offset_t mask, int flags, vm_map_read_t src_task,
		mach_vm_address_t src_address, boolean_t copy,
		vm_prot_t *cur_protection, vm_prot_t *max_protection,
		vm_inherit_t inheritance)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"_kernelrpc_mach_vm_remap_new(%p, %p, %p, %p, %p, %p, "
			"%p, %p, %p, %p, %p)\n",
			(void *)target_task, (void *)target_address,
			(void *)size, (void *)mask, (void *)flags,
			(void *)src_task, (void *)src_address, (void *)copy,
			(void *)cur_protection, (void *)max_protection,
			(void *)inheritance);
#endif
	if (!copy) {
		unimplemented();
	}

	return remap_copy(target_address, size, mask, flags, src_address,
			cur_protection);
}

kern_return_t
mach_vm_deferred_reclamation_buffer_allocate(task_t target_task,
		mach_vm_address_t *address, uint64_t *next_deadline,
		uint32_t len, uint32_t max_len)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_vm_deferred_reclamation_buffer_allocate(%p, %p, "
			"%p, %p, %p)\n",
			(void *)target_task, (void *)address,
			(void *)next_deadline, (void *)len, (void *)max_len);
#endif
	return KERN_NOT_SUPPORTED;
}

kern_return_t
mach_vm_deferred_reclamation_buffer_flush(task_t target_task,
		uint32_t num_entries_to_reclaim, uint64_t *bytes_reclaimed,
		uint64_t *next_deadline)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_vm_deferred_reclamation_buffer_flush(%p, %p, %p, "
			"%p)\n",
			(void *)target_task, (void *)num_entries_to_reclaim,
			(void *)bytes_reclaimed, (void *)next_deadline);
#endif
	unimplemented();
}

kern_return_t
mach_vm_range_create(vm_map_t target_task, mach_vm_range_flavor_t flavor,
		mach_vm_range_recipes_raw_t recipes,
		mach_msg_type_number_t recipesCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_vm_range_create(%p, %p, %p, %p)\n",
			(void *)target_task, (void *)flavor, (void *)recipes,
			(void *)recipesCnt);
#endif
	unimplemented();
}

kern_return_t
mach_vm_deferred_reclamation_buffer_resize(task_t target_task, uint32_t new_len,
		uint64_t *bytes_reclaimed, uint64_t *next_deadline)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_vm_deferred_reclamation_buffer_resize(%p, %p, "
			"%p, %p)\n",
			(void *)target_task, (void *)new_len,
			(void *)bytes_reclaimed, (void *)next_deadline);
#endif
	unimplemented();
}

kern_return_t
_kernelrpc_mach_vm_update_pointers_with_remote_tags(vm_map_t target,
		mach_vm_offset_list_t in_pointer_list,
		mach_msg_type_number_t in_pointer_listCnt,
		mach_vm_offset_list_t out_pointer_list,
		mach_msg_type_number_t *out_pointer_listCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"_kernelrpc_mach_vm_update_pointers_with_remote_tags(%"
			"p, %p, %p, %p, %p)\n",
			(void *)target, (void *)in_pointer_list,
			(void *)in_pointer_listCnt, (void *)out_pointer_list,
			(void *)out_pointer_listCnt);
#endif
	unimplemented();
}

kern_return_t
mach_vm_deferred_reclamation_buffer_query(task_read_t target,
		mach_vm_address_t *addr, mach_vm_size_t *size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_vm_deferred_reclamation_buffer_query(%p, %p, "
			"%p)\n",
			(void *)target, (void *)addr, (void *)size);
#endif
	unimplemented();
}

kern_return_t
_kernelrpc_mach_vm_reallocate(vm_map_t target_task, mach_vm_address_t src,
		mach_vm_size_t src_size, mach_vm_address_t *dst,
		mach_vm_size_t dst_size, mach_vm_offset_t align_mask,
		int options, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"_kernelrpc_mach_vm_reallocate(%p, %p, %p, %p, %p, %p, "
			"%p, %p)\n",
			(void *)target_task, (void *)src, (void *)src_size,
			(void *)dst, (void *)dst_size, (void *)align_mask,
			(void *)options, (void *)flags);
#endif
	unimplemented();
}
