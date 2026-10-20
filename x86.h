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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum x86_map {
	X86_MAP_PRIMARY,
	X86_MAP_0F,
	X86_MAP_0F38,
	X86_MAP_0F3A,
	X86_MAP_OTHER,
};

enum x86_flow {
	X86_FLOW_NONE,
	X86_FLOW_RELATIVE,
	X86_FLOW_OTHER,
};

struct x86_insn {
	uint8_t length;
	uint8_t rex;
	bool segment_override;
	bool address_size;
	bool vector;
	enum x86_map map;
	uint8_t opcode;
	bool has_modrm;
	uint8_t modrm_offset;
	uint8_t modrm;
	uint8_t disp_offset;
	uint8_t disp_size;
	bool rip_relative;
	uint8_t imm_offset;
	uint8_t imm_size;
	enum x86_flow flow;
};

bool x86_decode(const uint8_t *code, size_t available, struct x86_insn *insn);
int64_t x86_branch_target(const struct x86_insn *insn, const uint8_t *code,
		uint64_t address);
bool x86_is_sidt(const struct x86_insn *insn);
