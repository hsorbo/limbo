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

#pragma once

#include <mach-o/loader.h>
#include <stddef.h>
#include <stdint.h>

#define SIDT_PATCH_MAX 32

struct sidt_patch {
	uint64_t address;
	uint8_t length;
	uint8_t code[SIDT_PATCH_MAX];
};

struct sidt_patches {
	uint64_t trampoline_base;
	uint8_t *trampolines;
	size_t trampolines_size;
	size_t trampolines_capacity;
	struct sidt_patch *items;
	size_t count;
	size_t capacity;
};

void sidt_patches_init(struct sidt_patches *patches, uint64_t trampoline_base);
void sidt_patch_image(struct sidt_patches *patches,
		const struct mach_header_64 *header);
void sidt_patches_free(struct sidt_patches *patches);
