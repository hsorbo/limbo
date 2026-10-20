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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "sidt.h"
#include "x86.h"

#define MAX_CODE_SECTIONS 16
#define JUMP_LENGTH       5
#define TRAMPOLINE_MAX    256
#define RED_ZONE_SIZE     0x80
#define SAVED_STATE_SIZE  (3 * sizeof(uint64_t))
#define IDT_BASE          0xffffff8000000000ULL

#define LEA_RSP_BELOW_RED_ZONE     "\x48\x8d\x64\x24\x80"
#define LEA_RSP_ABOVE_RED_ZONE     "\x48\x8d\xa4\x24\x80\x00\x00\x00"
#define PUSHFQ                     "\x9c"
#define POPFQ                      "\x9d"
#define PUSH_RAX                   "\x50"
#define PUSH_RCX                   "\x51"
#define POP_RAX                    "\x58"
#define POP_RCX                    "\x59"
#define RDPID_RAX                  "\xf3\x0f\xc7\xf8"
#define AND_EAX_CPU_NUMBER_MASK    "\x25\xff\x0f\x00\x00"
#define OR_EAX_IDT_LIMIT_BASE      "\x0d\x00\x10\x00\x00"
#define MOV_AX_TO_RCX_TARGET       "\x66\x89\x01"
#define MOVABS_RAX                 "\x48\xb8"
#define MOV_RAX_TO_RCX_TARGET_BASE "\x48\x89\x41\x02"

struct code_range {
	uint64_t start;
	uint64_t end;
};

struct image {
	uint64_t slide;
	uint64_t text_address;
	const uint8_t *function_starts;
	uint32_t function_starts_size;
	const struct data_in_code_entry *data;
	uint32_t data_count;
	struct code_range sections[MAX_CODE_SECTIONS];
	uint32_t section_count;
};

struct decoded {
	uint64_t address;
	struct x86_insn insn;
};

struct function {
	struct decoded *insns;
	size_t count;
	size_t capacity;
	uint64_t *targets;
	size_t target_count;
	size_t target_capacity;
};

struct emitter {
	uint8_t code[TRAMPOLINE_MAX];
	size_t size;
	uint64_t address;
};

static bool parse_image(const struct mach_header_64 *header, struct image *img);
static void add_code_sections(
		struct image *img, const struct segment_command_64 *segment);
static bool may_contain_sidt(uint64_t start, uint64_t end);
static void scan_section(struct sidt_patches *patches, const struct image *img,
		const struct code_range *section);
static uint64_t read_uleb128(const uint8_t **cursor);
static void reset_function(struct function *fn);
static bool sweep_function(const struct image *img, uint64_t start,
		uint64_t end, struct function *fn);
static void patch_site(struct sidt_patches *patches, const struct function *fn,
		size_t index);
static const struct data_in_code_entry *find_data(
		const struct image *img, uint64_t address);
static void add_jump_table_targets(const struct image *img,
		const struct data_in_code_entry *entry, struct function *fn);
static bool is_zero_padding(uint64_t start, uint64_t end);
static void add_insn(struct function *fn, uint64_t address,
		const struct x86_insn *insn);
static void add_target(struct function *fn, uint64_t target);
static int compare_addresses(const void *a, const void *b);
static bool is_target(const struct function *fn, uint64_t address);
static bool emit_trampoline(struct emitter *e, const struct decoded *sidt,
		const struct decoded *displaced, size_t displaced_count,
		uint64_t resume);
static void commit_patch(struct sidt_patches *patches, uint64_t address,
		size_t length, const struct emitter *e);
static void emit_operand_address(struct emitter *e, const struct decoded *sidt);
static bool emit_relocated(struct emitter *e, const struct decoded *d);
static bool emit_jump(struct emitter *e, uint64_t target);
static int64_t read_displacement(const struct decoded *d);
static bool fits_int32(int64_t value);
static void emit_u32(struct emitter *e, uint32_t value);
static void emit_bytes(struct emitter *e, const void *bytes, size_t size);

void
sidt_patches_init(struct sidt_patches *patches, uint64_t trampoline_base)
{
	memset(patches, 0, sizeof(*patches));
	patches->trampoline_base = trampoline_base;
}

void
sidt_patch_image(struct sidt_patches *patches,
		const struct mach_header_64 *header)
{
	struct image img;
	if (!parse_image(header, &img)) {
		return;
	}

	for (uint32_t i = 0; i < img.section_count; i++) {
		if (may_contain_sidt(img.sections[i].start,
				    img.sections[i].end)) {
			scan_section(patches, &img, &img.sections[i]);
		}
	}
}

void
sidt_patches_free(struct sidt_patches *patches)
{
	free(patches->trampolines);
	free(patches->items);
}

static bool
parse_image(const struct mach_header_64 *header, struct image *img)
{
	memset(img, 0, sizeof(*img));

	const struct linkedit_data_command *function_starts = NULL;
	const struct linkedit_data_command *data_in_code = NULL;
	const struct segment_command_64 *linkedit = NULL;
	const struct load_command *command
			= (const struct load_command *)(header + 1);
	for (uint32_t i = 0; i < header->ncmds; i++) {
		if (command->cmd == LC_SEGMENT_64) {
			const struct segment_command_64 *segment
					= (const void *)command;
			if (strcmp(segment->segname, SEG_TEXT) == 0) {
				img->slide = (uint64_t)header - segment->vmaddr;
				img->text_address = (uint64_t)header;
			} else if (strcmp(segment->segname, SEG_LINKEDIT)
					== 0) {
				linkedit = segment;
			}

			add_code_sections(img, segment);
		} else if (command->cmd == LC_FUNCTION_STARTS) {
			function_starts = (const void *)command;
		} else if (command->cmd == LC_DATA_IN_CODE) {
			data_in_code = (const void *)command;
		}
		command = (const void *)((const uint8_t *)command
				+ command->cmdsize);
	}

	if (function_starts == NULL || linkedit == NULL) {
		return false;
	}

	uint64_t linkedit_base
			= linkedit->vmaddr + img->slide - linkedit->fileoff;
	img->function_starts = (const uint8_t *)(linkedit_base
			+ function_starts->dataoff);
	img->function_starts_size = function_starts->datasize;
	if (data_in_code != NULL) {
		img->data = (const void *)(linkedit_base
				+ data_in_code->dataoff);
		img->data_count = data_in_code->datasize
				/ sizeof(struct data_in_code_entry);
	}
	for (uint32_t i = 0; i < img->section_count; i++) {
		img->sections[i].start += img->slide;
		img->sections[i].end += img->slide;
	}
	return true;
}

static void
add_code_sections(struct image *img, const struct segment_command_64 *segment)
{
	const struct section_64 *sections = (const void *)(segment + 1);
	for (uint32_t i = 0; i < segment->nsects
			&& img->section_count < MAX_CODE_SECTIONS;
			i++) {
		const struct section_64 *section = &sections[i];
		if (section->flags
				& (S_ATTR_PURE_INSTRUCTIONS
						| S_ATTR_SOME_INSTRUCTIONS)) {
			img->sections[img->section_count++] = (struct
					code_range){
					section->addr,
					section->addr + section->size,
			};
		}
	}
}

static bool
may_contain_sidt(uint64_t start, uint64_t end)
{
	return memmem((const void *)start, end - start, "\x0f\x01", 2) != NULL;
}

static void
scan_section(struct sidt_patches *patches, const struct image *img,
		const struct code_range *section)
{
	struct function fn = {0};
	const uint8_t *cursor = img->function_starts;
	const uint8_t *end = cursor + img->function_starts_size;
	uint64_t start = img->text_address;
	uint64_t delta;
	while (cursor < end && (delta = read_uleb128(&cursor)) != 0) {
		start += delta;
		if (start >= section->end) {
			break;
		}
		if (start < section->start) {
			continue;
		}

		uint64_t next = start;
		const uint8_t *lookahead = cursor;
		uint64_t next_delta;
		if (lookahead < end
				&& (next_delta = read_uleb128(&lookahead))
						!= 0) {
			next += next_delta;
		}
		uint64_t function_end = (next == start || next > section->end)
				? section->end
				: next;

		if (!may_contain_sidt(start, function_end)) {
			continue;
		}
		reset_function(&fn);
		if (!sweep_function(img, start, function_end, &fn)) {
			continue;
		}
		for (size_t i = 0; i < fn.count; i++) {
			if (x86_is_sidt(&fn.insns[i].insn)) {
				patch_site(patches, &fn, i);
			}
		}
	}
	free(fn.insns);
	free(fn.targets);
}

static uint64_t
read_uleb128(const uint8_t **cursor)
{
	uint64_t value = 0;
	unsigned shift = 0;
	uint8_t byte;
	do {
		byte = *(*cursor)++;
		value |= (uint64_t)(byte & 0x7f) << shift;
		shift += 7;
	} while (byte & 0x80);
	return value;
}

static void
reset_function(struct function *fn)
{
	fn->count = 0;
	fn->target_count = 0;
}

static bool
sweep_function(const struct image *img, uint64_t start, uint64_t end,
		struct function *fn)
{
	uint64_t address = start;
	while (address < end) {
		const struct data_in_code_entry *entry
				= find_data(img, address);
		if (entry != NULL) {
			add_jump_table_targets(img, entry, fn);
			address = img->text_address + entry->offset
					+ entry->length;
			continue;
		}

		struct x86_insn insn;
		if (!x86_decode((const uint8_t *)address, end - address,
				    &insn)) {
			return is_zero_padding(address, end);
		}
		add_insn(fn, address, &insn);
		if (insn.flow == X86_FLOW_RELATIVE) {
			add_target(fn,
					x86_branch_target(&insn,
							(const uint8_t *)
									address,
							address));
		}
		address += insn.length;
	}

	qsort(fn->targets, fn->target_count, sizeof(uint64_t),
			compare_addresses);
	return true;
}

static void
patch_site(struct sidt_patches *patches, const struct function *fn,
		size_t index)
{
	const struct decoded *sidt = &fn->insns[index];
	if (sidt->insn.segment_override || sidt->insn.address_size) {
		return;
	}

	size_t length = sidt->insn.length;
	size_t end = index + 1;
	while (length < JUMP_LENGTH) {
		if (end == fn->count) {
			return;
		}
		const struct decoded *next = &fn->insns[end];
		if (next->address != sidt->address + length
				|| next->insn.flow != X86_FLOW_NONE
				|| is_target(fn, next->address)) {
			return;
		}
		length += next->insn.length;
		end++;
	}

	struct emitter e = {
			.address
			= patches->trampoline_base + patches->trampolines_size,
	};
	if (!emit_trampoline(&e, sidt, sidt + 1, end - index - 1,
			    sidt->address + length)) {
		return;
	}
	commit_patch(patches, sidt->address, length, &e);
}

static const struct data_in_code_entry *
find_data(const struct image *img, uint64_t address)
{
	uint64_t offset = address - img->text_address;
	size_t low = 0;
	size_t high = img->data_count;
	while (low < high) {
		size_t middle = (low + high) / 2;
		const struct data_in_code_entry *entry = &img->data[middle];
		if (offset < entry->offset) {
			high = middle;
		} else if (offset >= (uint64_t)entry->offset + entry->length) {
			low = middle + 1;
		} else {
			return entry;
		}
	}
	return NULL;
}

static void
add_jump_table_targets(const struct image *img,
		const struct data_in_code_entry *entry, struct function *fn)
{
	if (entry->kind != DICE_KIND_JUMP_TABLE32) {
		return;
	}

	uint64_t table = img->text_address + entry->offset;
	for (uint32_t i = 0; i + sizeof(int32_t) <= entry->length;
			i += sizeof(int32_t)) {
		int32_t displacement;
		memcpy(&displacement, (const void *)(table + i),
				sizeof(displacement));
		add_target(fn, table + displacement);
	}
}

static bool
is_zero_padding(uint64_t start, uint64_t end)
{
	for (const uint8_t *p = (const uint8_t *)start;
			p != (const uint8_t *)end; p++) {
		if (*p != 0) {
			return false;
		}
	}
	return true;
}

static void
add_insn(struct function *fn, uint64_t address, const struct x86_insn *insn)
{
	if (fn->count == fn->capacity) {
		fn->capacity = fn->capacity ? fn->capacity * 2 : 256;
		fn->insns = realloc(fn->insns,
				fn->capacity * sizeof(struct decoded));
	}
	fn->insns[fn->count++] = (struct decoded){address, *insn};
}

static void
add_target(struct function *fn, uint64_t target)
{
	if (fn->target_count == fn->target_capacity) {
		fn->target_capacity = fn->target_capacity
				? fn->target_capacity * 2
				: 64;
		fn->targets = realloc(fn->targets,
				fn->target_capacity * sizeof(uint64_t));
	}
	fn->targets[fn->target_count++] = target;
}

static int
compare_addresses(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a;
	uint64_t y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

static bool
is_target(const struct function *fn, uint64_t address)
{
	return bsearch(&address, fn->targets, fn->target_count,
			       sizeof(uint64_t), compare_addresses)
			!= NULL;
}

static bool
emit_trampoline(struct emitter *e, const struct decoded *sidt,
		const struct decoded *displaced, size_t displaced_count,
		uint64_t resume)
{
	static const char enter[]
			= LEA_RSP_BELOW_RED_ZONE PUSHFQ PUSH_RAX PUSH_RCX;
	static const char store_limit[] = RDPID_RAX AND_EAX_CPU_NUMBER_MASK
			OR_EAX_IDT_LIMIT_BASE MOV_AX_TO_RCX_TARGET MOVABS_RAX;
	static const char store_base_and_leave[]
			= MOV_RAX_TO_RCX_TARGET_BASE POP_RCX POP_RAX POPFQ
					LEA_RSP_ABOVE_RED_ZONE;
	uint64_t idt_base = IDT_BASE;

	emit_bytes(e, enter, sizeof(enter) - 1);
	emit_operand_address(e, sidt);
	emit_bytes(e, store_limit, sizeof(store_limit) - 1);
	emit_bytes(e, &idt_base, sizeof(idt_base));
	emit_bytes(e, store_base_and_leave, sizeof(store_base_and_leave) - 1);
	for (size_t i = 0; i < displaced_count; i++) {
		if (!emit_relocated(e, &displaced[i])) {
			return false;
		}
	}
	return emit_jump(e, resume);
}

static void
commit_patch(struct sidt_patches *patches, uint64_t address, size_t length,
		const struct emitter *e)
{
	if (patches->trampolines_size + e->size
			> patches->trampolines_capacity) {
		patches->trampolines_capacity = patches->trampolines_capacity
				? patches->trampolines_capacity * 2
				: 4096;
		patches->trampolines = realloc(patches->trampolines,
				patches->trampolines_capacity);
	}
	memcpy(patches->trampolines + patches->trampolines_size, e->code,
			e->size);
	patches->trampolines_size += e->size;

	if (patches->count == patches->capacity) {
		patches->capacity = patches->capacity ? patches->capacity * 2
						      : 64;
		patches->items = realloc(patches->items,
				patches->capacity * sizeof(struct sidt_patch));
	}
	struct sidt_patch *patch = &patches->items[patches->count++];
	patch->address = address;
	patch->length = length;
	memset(patch->code, 0xcc, sizeof(patch->code));
	patch->code[0] = 0xe9;
	int32_t displacement = e->address - (address + JUMP_LENGTH);
	memcpy(patch->code + 1, &displacement, sizeof(displacement));
}

static void
emit_operand_address(struct emitter *e, const struct decoded *sidt)
{
	const struct x86_insn *insn = &sidt->insn;
	const uint8_t *code = (const uint8_t *)sidt->address;
	uint8_t rex = 0x48 | (insn->rex & 0x3);
	uint8_t mod = insn->modrm >> 6;
	uint8_t rm = insn->modrm & 7;

	if (insn->rip_relative) {
		uint64_t target = sidt->address + insn->length
				+ read_displacement(sidt);
		emit_bytes(e, (uint8_t[]){0x48, 0x8d, 0x0d}, 3);
		emit_u32(e, target - (e->address + e->size + sizeof(uint32_t)));
		return;
	}

	const uint8_t *sib = code + insn->modrm_offset + 1;
	bool based_on_stack = rm == 4 && (*sib & 7) == 4 && !(insn->rex & 0x1);
	if (based_on_stack) {
		emit_bytes(e, (uint8_t[]){rex, 0x8d, 0x8c, *sib}, 4);
		emit_u32(e,
				read_displacement(sidt) + RED_ZONE_SIZE
						+ SAVED_STATE_SIZE);
		return;
	}

	emit_bytes(e,
			(uint8_t[]){rex, 0x8d,
					(uint8_t)((mod << 6) | (1 << 3) | rm)},
			3);
	emit_bytes(e, code + insn->modrm_offset + 1,
			insn->disp_offset + insn->disp_size
					- (insn->modrm_offset + 1));
}

static bool
emit_relocated(struct emitter *e, const struct decoded *d)
{
	size_t start = e->size;
	emit_bytes(e, (const void *)d->address, d->insn.length);
	if (!d->insn.rip_relative) {
		return true;
	}

	uint64_t target = d->address + d->insn.length + read_displacement(d);
	int64_t displacement = target - (e->address + start + d->insn.length);
	if (!fits_int32(displacement)) {
		return false;
	}
	int32_t value = displacement;
	memcpy(e->code + start + d->insn.disp_offset, &value, sizeof(value));
	return true;
}

static bool
emit_jump(struct emitter *e, uint64_t target)
{
	int64_t displacement = target - (e->address + e->size + JUMP_LENGTH);
	if (!fits_int32(displacement)) {
		return false;
	}
	emit_bytes(e, (uint8_t[]){0xe9}, 1);
	emit_u32(e, displacement);
	return true;
}

static int64_t
read_displacement(const struct decoded *d)
{
	const uint8_t *code = (const uint8_t *)d->address + d->insn.disp_offset;
	if (d->insn.disp_size == 1) {
		return (int8_t)code[0];
	}
	if (d->insn.disp_size == 4) {
		int32_t value;
		memcpy(&value, code, sizeof(value));
		return value;
	}
	return 0;
}

static bool
fits_int32(int64_t value)
{
	return value >= INT32_MIN && value <= INT32_MAX;
}

static void
emit_u32(struct emitter *e, uint32_t value)
{
	emit_bytes(e, &value, sizeof(value));
}

static void
emit_bytes(struct emitter *e, const void *bytes, size_t size)
{
	memcpy(e->code + e->size, bytes, size);
	e->size += size;
}
