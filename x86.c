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

#include <string.h>

#include "x86.h"

#define MAX_LENGTH 15

struct prefixes {
	bool operand_size;
	bool address_size;
	bool repne;
	bool segment;
};

static bool apply_prefix(uint8_t b, struct prefixes *p);
static bool decode_vector(const uint8_t *code, size_t available, size_t *offset,
		struct x86_insn *insn);
static bool decode_legacy_opcode(const uint8_t *code, size_t available,
		size_t *offset, struct x86_insn *insn);
static bool decode_modrm(const uint8_t *code, size_t available, size_t *offset,
		bool address_size, struct x86_insn *insn);
static bool primary_is_invalid(uint8_t op);
static uint8_t primary_imm_size(uint8_t op, uint8_t modrm, uint8_t rex,
		const struct prefixes *p);
static enum x86_flow primary_flow(uint8_t op, uint8_t modrm);
static bool secondary_is_invalid(uint8_t op);
static uint8_t secondary_imm_size(uint8_t op, const struct prefixes *p);
static uint8_t vector_imm_size(enum x86_map map, uint8_t op);
static bool primary_has_modrm(uint8_t op);
static bool secondary_has_modrm(uint8_t op);

bool
x86_decode(const uint8_t *code, size_t available, struct x86_insn *insn)
{
	memset(insn, 0, sizeof(*insn));
	if (available > MAX_LENGTH) {
		available = MAX_LENGTH;
	}

	struct prefixes p = {0};
	size_t offset = 0;
	while (offset < available && apply_prefix(code[offset], &p)) {
		offset++;
	}
	if (offset < available && (code[offset] & 0xf0) == 0x40) {
		insn->rex = code[offset++];
	}
	if (offset >= available) {
		return false;
	}
	insn->segment_override = p.segment;
	insn->address_size = p.address_size;

	uint8_t b = code[offset];
	bool ok;
	if (b == 0xc4 || b == 0xc5 || b == 0x62
			|| (b == 0x8f && offset + 1 < available
					&& (code[offset + 1] & 0x1f) >= 8)) {
		ok = !insn->rex
				&& decode_vector(
						code, available, &offset, insn);
	} else {
		ok = decode_legacy_opcode(code, available, &offset, insn);
	}
	if (!ok) {
		return false;
	}

	if (insn->has_modrm
			&& !decode_modrm(code, available, &offset,
					p.address_size, insn)) {
		return false;
	}

	if (!insn->vector) {
		if (insn->map == X86_MAP_PRIMARY) {
			if (primary_is_invalid(insn->opcode)) {
				return false;
			}
			insn->imm_size = primary_imm_size(insn->opcode,
					insn->modrm, insn->rex, &p);
			insn->flow = primary_flow(insn->opcode, insn->modrm);
		} else if (insn->map == X86_MAP_0F) {
			if (secondary_is_invalid(insn->opcode)) {
				return false;
			}
			insn->imm_size = secondary_imm_size(insn->opcode, &p);
			if (insn->opcode >= 0x80 && insn->opcode <= 0x8f) {
				insn->flow = X86_FLOW_RELATIVE;
			} else if (insn->opcode == 0x05 || insn->opcode == 0x07
					|| insn->opcode == 0x0b
					|| insn->opcode == 0x34
					|| insn->opcode == 0x35) {
				insn->flow = X86_FLOW_OTHER;
			}
		} else if (insn->map == X86_MAP_0F3A) {
			insn->imm_size = 1;
		}
	}

	insn->imm_offset = offset;
	offset += insn->imm_size;
	if (offset > available) {
		return false;
	}
	insn->length = offset;
	return true;
}

int64_t
x86_branch_target(const struct x86_insn *insn, const uint8_t *code,
		uint64_t address)
{
	int64_t displacement;
	if (insn->imm_size == 1) {
		displacement = (int8_t)code[insn->imm_offset];
	} else {
		int32_t value;
		memcpy(&value, code + insn->imm_offset, sizeof(value));
		displacement = value;
	}
	return address + insn->length + displacement;
}

bool
x86_is_sidt(const struct x86_insn *insn)
{
	return !insn->vector && insn->map == X86_MAP_0F && insn->opcode == 0x01
			&& (insn->modrm >> 6) != 3
			&& ((insn->modrm >> 3) & 7) == 1;
}

static bool
apply_prefix(uint8_t b, struct prefixes *p)
{
	switch (b) {
	case 0x66:
		p->operand_size = true;
		return true;
	case 0x67:
		p->address_size = true;
		return true;
	case 0xf2:
		p->repne = true;
		return true;
	case 0xf0:
	case 0xf3:
		return true;
	case 0x26:
	case 0x2e:
	case 0x36:
	case 0x3e:
	case 0x64:
	case 0x65:
		p->segment = true;
		return true;
	default:
		return false;
	}
}

static bool
decode_vector(const uint8_t *code, size_t available, size_t *offset,
		struct x86_insn *insn)
{
	uint8_t kind = code[*offset];
	size_t payload = (kind == 0xc5) ? 1 : (kind == 0x62) ? 3 : 2;
	if (*offset + 1 + payload + 1 > available) {
		return false;
	}

	uint8_t select = code[*offset + 1] & 0x1f;
	if (kind == 0xc5) {
		select = 1;
	} else if (kind == 0x62) {
		select &= 0x7;
	}

	insn->vector = true;
	switch (kind == 0x8f ? 0 : select) {
	case 1:
		insn->map = X86_MAP_0F;
		break;
	case 2:
		insn->map = X86_MAP_0F38;
		break;
	case 3:
		insn->map = X86_MAP_0F3A;
		break;
	case 5:
	case 6:
		if (kind != 0x62) {
			return false;
		}
		insn->map = X86_MAP_OTHER;
		break;
	case 0:
		if (select > 0xa) {
			return false;
		}
		insn->map = X86_MAP_OTHER;
		break;
	default:
		return false;
	}

	*offset += 1 + payload;
	insn->opcode = code[(*offset)++];
	insn->has_modrm = !(kind != 0x62 && insn->map == X86_MAP_0F
			&& insn->opcode == 0x77);
	if (kind == 0x8f) {
		insn->imm_size = (select == 0x8) ? 1 : (select == 0xa) ? 4 : 0;
	} else {
		insn->imm_size = vector_imm_size(insn->map, insn->opcode);
	}
	return true;
}

static bool
decode_legacy_opcode(const uint8_t *code, size_t available, size_t *offset,
		struct x86_insn *insn)
{
	uint8_t b = code[(*offset)++];
	if (b != 0x0f) {
		insn->map = X86_MAP_PRIMARY;
		insn->opcode = b;
		insn->has_modrm = primary_has_modrm(b);
		return true;
	}

	if (*offset >= available) {
		return false;
	}
	b = code[(*offset)++];
	if (b == 0x38 || b == 0x3a) {
		if (*offset >= available) {
			return false;
		}
		insn->map = (b == 0x38) ? X86_MAP_0F38 : X86_MAP_0F3A;
		insn->opcode = code[(*offset)++];
		insn->has_modrm = true;
		return true;
	}

	insn->map = X86_MAP_0F;
	insn->opcode = b;
	insn->has_modrm = secondary_has_modrm(b);
	return true;
}

static bool
decode_modrm(const uint8_t *code, size_t available, size_t *offset,
		bool address_size, struct x86_insn *insn)
{
	if (*offset >= available) {
		return false;
	}
	insn->modrm_offset = *offset;
	insn->modrm = code[(*offset)++];

	uint8_t mod = insn->modrm >> 6;
	uint8_t rm = insn->modrm & 7;
	if (mod == 3) {
		return true;
	}

	if (rm == 4) {
		if (*offset >= available) {
			return false;
		}
		uint8_t sib = code[(*offset)++];
		if (mod == 0 && (sib & 7) == 5) {
			insn->disp_size = 4;
		}
	} else if (mod == 0 && rm == 5) {
		insn->disp_size = 4;
		insn->rip_relative = !address_size;
	}
	if (mod == 1) {
		insn->disp_size = 1;
	} else if (mod == 2) {
		insn->disp_size = 4;
	}

	insn->disp_offset = *offset;
	*offset += insn->disp_size;
	return *offset <= available;
}

static bool
primary_is_invalid(uint8_t op)
{
	switch (op) {
	case 0x06:
	case 0x07:
	case 0x0e:
	case 0x16:
	case 0x17:
	case 0x1e:
	case 0x1f:
	case 0x27:
	case 0x2f:
	case 0x37:
	case 0x3f:
	case 0x60:
	case 0x61:
	case 0x82:
	case 0x9a:
	case 0xce:
	case 0xd4:
	case 0xd5:
	case 0xd6:
	case 0xea:
		return true;
	default:
		return false;
	}
}

static uint8_t
primary_imm_size(uint8_t op, uint8_t modrm, uint8_t rex,
		const struct prefixes *p)
{
	uint8_t z = p->operand_size ? 2 : 4;
	uint8_t reg = (modrm >> 3) & 7;

	if (op < 0x40) {
		switch (op & 7) {
		case 4:
			return 1;
		case 5:
			return z;
		default:
			return 0;
		}
	}
	if ((op >= 0x70 && op <= 0x7f) || (op >= 0xb0 && op <= 0xb7)
			|| (op >= 0xe0 && op <= 0xe7)) {
		return 1;
	}
	if (op >= 0xb8 && op <= 0xbf) {
		return (rex & 0x8) ? 8 : z;
	}
	if (op >= 0xa0 && op <= 0xa3) {
		return p->address_size ? 4 : 8;
	}
	switch (op) {
	case 0x6a:
	case 0x6b:
	case 0x80:
	case 0x83:
	case 0xa8:
	case 0xc0:
	case 0xc1:
	case 0xc6:
	case 0xcd:
	case 0xeb:
		return 1;
	case 0x68:
	case 0x69:
	case 0x81:
	case 0xa9:
	case 0xc7:
		return z;
	case 0xe8:
	case 0xe9:
		return 4;
	case 0xc2:
	case 0xca:
		return 2;
	case 0xc8:
		return 3;
	case 0xf6:
		return (reg < 2) ? 1 : 0;
	case 0xf7:
		return (reg < 2) ? z : 0;
	default:
		return 0;
	}
}

static enum x86_flow
primary_flow(uint8_t op, uint8_t modrm)
{
	uint8_t reg = (modrm >> 3) & 7;
	if ((op >= 0x70 && op <= 0x7f) || (op >= 0xe0 && op <= 0xe3)
			|| op == 0xe8 || op == 0xe9 || op == 0xeb
			|| (op == 0xc7 && modrm == 0xf8)) {
		return X86_FLOW_RELATIVE;
	}
	switch (op) {
	case 0xc2:
	case 0xc3:
	case 0xca:
	case 0xcb:
	case 0xcc:
	case 0xcd:
	case 0xcf:
	case 0xf4:
		return X86_FLOW_OTHER;
	case 0xff:
		return (reg >= 2 && reg <= 5) ? X86_FLOW_OTHER : X86_FLOW_NONE;
	default:
		return X86_FLOW_NONE;
	}
}

static bool
secondary_is_invalid(uint8_t op)
{
	switch (op) {
	case 0x04:
	case 0x0a:
	case 0x0c:
	case 0x0f:
	case 0x24:
	case 0x25:
	case 0x26:
	case 0x27:
	case 0x36:
	case 0x39:
	case 0x3b:
	case 0x3c:
	case 0x3d:
	case 0x3e:
	case 0x3f:
	case 0x7a:
	case 0x7b:
	case 0xa6:
	case 0xa7:
		return true;
	default:
		return false;
	}
}

static uint8_t
secondary_imm_size(uint8_t op, const struct prefixes *p)
{
	if (op >= 0x70 && op <= 0x73) {
		return 1;
	}
	if (op >= 0x80 && op <= 0x8f) {
		return 4;
	}
	switch (op) {
	case 0xa4:
	case 0xac:
	case 0xba:
	case 0xc2:
	case 0xc4:
	case 0xc5:
	case 0xc6:
		return 1;
	case 0x78:
		return (p->operand_size || p->repne) ? 2 : 0;
	default:
		return 0;
	}
}

static uint8_t
vector_imm_size(enum x86_map map, uint8_t op)
{
	if (map == X86_MAP_0F3A) {
		return 1;
	}
	if (map != X86_MAP_0F) {
		return 0;
	}
	if (op >= 0x70 && op <= 0x73) {
		return 1;
	}
	switch (op) {
	case 0xc2:
	case 0xc4:
	case 0xc5:
	case 0xc6:
		return 1;
	default:
		return 0;
	}
}

static bool
primary_has_modrm(uint8_t op)
{
	if (op < 0x40) {
		return (op & 7) < 4;
	}
	if (op >= 0x80 && op <= 0x8f) {
		return true;
	}
	if (op >= 0xd0 && op <= 0xd3) {
		return true;
	}
	if (op >= 0xd8 && op <= 0xdf) {
		return true;
	}
	switch (op) {
	case 0x63:
	case 0x69:
	case 0x6b:
	case 0xc0:
	case 0xc1:
	case 0xc6:
	case 0xc7:
	case 0xf6:
	case 0xf7:
	case 0xfe:
	case 0xff:
		return true;
	default:
		return false;
	}
}

static bool
secondary_has_modrm(uint8_t op)
{
	if ((op >= 0x30 && op <= 0x37) || (op >= 0x80 && op <= 0x8f)
			|| (op >= 0xc8 && op <= 0xcf)) {
		return false;
	}
	switch (op) {
	case 0x05:
	case 0x06:
	case 0x07:
	case 0x08:
	case 0x09:
	case 0x0b:
	case 0x0e:
	case 0x77:
	case 0xa0:
	case 0xa1:
	case 0xa2:
	case 0xa8:
	case 0xa9:
	case 0xaa:
		return false;
	default:
		return true;
	}
}
