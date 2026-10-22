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

#include "libinfo.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipc.h"
#include "sysroot.h"

#define LIBINFO_HANDSHAKE_ID 0x77303074
#define LIBINFO_REPLY_ID 0x20000000

#define XPC_SERIAL_MAGIC 0x40585043
#define XPC_SERIAL_VERSION 5
#define XPC_SERIAL_INT64 0x3000
#define XPC_SERIAL_UINT64 0x4000
#define XPC_SERIAL_STRING 0x9000
#define XPC_SERIAL_UUID 0xa000
#define XPC_SERIAL_DICTIONARY 0xf000

struct passwd_entry {
	char name[256];
	char passwd[256];
	uint64_t uid;
	uint64_t gid;
	char gecos[256];
	char dir[256];
	char shell[256];
};

struct xpc_builder {
	uint8_t *buffer;
	uint32_t offset;
	uint32_t dictionary_size_offset;
};

struct xpc_reader {
	const uint8_t *position;
	const uint8_t *end;
};

static void adopt_request_port(mach_msg_header_t *request);
static bool read_query(mach_msg_header_t *request, char *rpc_name,
		size_t rpc_name_size, uint64_t *uid);
static bool passwd_lookup(uint64_t uid, struct passwd_entry *out);
static void reply_with_passwd(mach_msg_header_t *request,
		const struct passwd_entry *entry);
static void reply_empty(mach_msg_header_t *request);

static uint32_t read_u32(struct xpc_reader *reader);
static uint64_t read_u64(struct xpc_reader *reader);
static const char *read_key(struct xpc_reader *reader);
static void reader_align(struct xpc_reader *reader);

static void begin_dictionary(struct xpc_builder *builder, uint32_t count);
static void end_dictionary(struct xpc_builder *builder);
static void append_string(struct xpc_builder *builder, const char *key,
		const char *value);
static void append_int64(struct xpc_builder *builder, const char *key,
		uint64_t value);
static void append_uuid(struct xpc_builder *builder, const char *key,
		const uint8_t *value);
static void append_key(struct xpc_builder *builder, const char *key);
static void append_u32(struct xpc_builder *builder, uint32_t value);
static void append_u64(struct xpc_builder *builder, uint64_t value);
static void builder_align(struct xpc_builder *builder);

bool
libinfo_is_handshake(mach_msg_id_t id)
{
	return id == LIBINFO_HANDSHAKE_ID;
}

void
libinfo_serve(mach_msg_header_t *request)
{
	if (libinfo_is_handshake(request->msgh_id)) {
		adopt_request_port(request);
		return;
	}

	char rpc_name[64] = { 0 };
	uint64_t uid = 0;
	struct passwd_entry entry;
	if (read_query(request, rpc_name, sizeof(rpc_name), &uid)
			&& strcmp(rpc_name, "getpwuid") == 0
			&& passwd_lookup(uid, &entry)) {
		reply_with_passwd(request, &entry);
	} else {
		reply_empty(request);
	}
}

static void
adopt_request_port(mach_msg_header_t *request)
{
	mach_msg_body_t *body = (mach_msg_body_t *)(request + 1);
	mach_msg_port_descriptor_t *descriptor
			= (mach_msg_port_descriptor_t *)(body + 1);
	for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count; i++) {
		if (descriptor->disposition == MACH_MSG_TYPE_PORT_RECEIVE) {
			ipc_port_adopt_kotype(descriptor->name,
					IPC_KOBJECT_LIBINFO);
		}
		descriptor++;
	}
}

static bool
read_query(mach_msg_header_t *request, char *rpc_name, size_t rpc_name_size,
		uint64_t *uid)
{
	struct xpc_reader reader = {
		.position = (const uint8_t *)(request + 1),
		.end = (const uint8_t *)request + request->msgh_size,
	};
	if (read_u32(&reader) != XPC_SERIAL_MAGIC) {
		return false;
	}
	read_u32(&reader);
	if (read_u32(&reader) != XPC_SERIAL_DICTIONARY) {
		return false;
	}
	read_u32(&reader);
	uint32_t count = read_u32(&reader);

	bool have_name = false;
	for (uint32_t i = 0; i < count; i++) {
		const char *key = read_key(&reader);
		uint32_t type = read_u32(&reader);
		switch (type) {
		case XPC_SERIAL_INT64:
		case XPC_SERIAL_UINT64: {
			uint64_t value = read_u64(&reader);
			if (strcmp(key, "uid") == 0) {
				*uid = value;
			}
			break;
		}
		case XPC_SERIAL_STRING: {
			uint32_t length = read_u32(&reader);
			if (strcmp(key, "rpc_name") == 0) {
				strncpy(rpc_name, (const char *)reader.position,
						rpc_name_size - 1);
				have_name = true;
			}
			reader.position += length;
			reader_align(&reader);
			break;
		}
		default:
			return false;
		}
	}
	return have_name;
}

static bool
passwd_lookup(uint64_t uid, struct passwd_entry *out)
{
	char host_path[PATH_MAX];
	FILE *file = fopen(sysroot_host_path("/etc/passwd", 0, host_path), "r");
	if (file == NULL) {
		return false;
	}

	bool found = false;
	char line[1024];
	while (fgets(line, sizeof(line), file) != NULL) {
		if (line[0] == '#' || line[0] == '\n') {
			continue;
		}
		struct passwd_entry entry = { 0 };
		char *change = NULL;
		char *expire = NULL;
		if (sscanf(line,
				    "%255[^:]:%255[^:]:%llu:%llu:%255[^:]:%255[^:]:%255[^:\n]",
				    entry.name, entry.passwd,
				    (unsigned long long *)&entry.uid,
				    (unsigned long long *)&entry.gid, entry.gecos,
				    entry.dir, entry.shell)
				< 7) {
			continue;
		}
		(void)change;
		(void)expire;
		if (entry.uid == uid) {
			*out = entry;
			found = true;
			break;
		}
	}

	fclose(file);
	return found;
}

static void
reply_with_passwd(mach_msg_header_t *request, const struct passwd_entry *entry)
{
	uint8_t storage[1024] = { 0 };
	mach_msg_header_t *reply = (mach_msg_header_t *)storage;

	struct xpc_builder builder = {
		.buffer = (uint8_t *)(reply + 1),
		.offset = 0,
	};
	uint8_t uuid[16] = { 0xff, 0xff, 0xee, 0xee, 0xdd, 0xdd, 0xcc, 0xcc,
		0xbb, 0xbb, 0xaa, 0xaa, entry->uid >> 24, entry->uid >> 16,
		entry->uid >> 8, entry->uid };

	append_u32(&builder, XPC_SERIAL_MAGIC);
	append_u32(&builder, XPC_SERIAL_VERSION);
	begin_dictionary(&builder, 9);
	append_string(&builder, "pw_name", entry->name);
	append_string(&builder, "pw_passwd", entry->passwd);
	append_int64(&builder, "pw_uid", entry->uid);
	append_int64(&builder, "pw_gid", entry->gid);
	append_string(&builder, "pw_gecos", entry->gecos);
	append_string(&builder, "pw_dir", entry->dir);
	append_string(&builder, "pw_shell", entry->shell);
	append_uuid(&builder, "pw_uuid", uuid);
	append_int64(&builder, "rpc_version", 2);
	end_dictionary(&builder);

	reply->msgh_bits = MACH_MSGH_BITS(
			MACH_MSGH_BITS_REMOTE(request->msgh_bits), 0);
	reply->msgh_remote_port = request->msgh_remote_port;
	reply->msgh_local_port = MACH_PORT_NULL;
	reply->msgh_id = LIBINFO_REPLY_ID;
	reply->msgh_size = sizeof(*reply) + builder.offset;

	ipc_kernel_send(reply);
}

static void
reply_empty(mach_msg_header_t *request)
{
	uint8_t storage[64] = { 0 };
	mach_msg_header_t *reply = (mach_msg_header_t *)storage;

	struct xpc_builder builder = {
		.buffer = (uint8_t *)(reply + 1),
		.offset = 0,
	};
	append_u32(&builder, XPC_SERIAL_MAGIC);
	append_u32(&builder, XPC_SERIAL_VERSION);
	begin_dictionary(&builder, 0);
	end_dictionary(&builder);

	reply->msgh_bits = MACH_MSGH_BITS(
			MACH_MSGH_BITS_REMOTE(request->msgh_bits), 0);
	reply->msgh_remote_port = request->msgh_remote_port;
	reply->msgh_local_port = MACH_PORT_NULL;
	reply->msgh_id = LIBINFO_REPLY_ID;
	reply->msgh_size = sizeof(*reply) + builder.offset;

	ipc_kernel_send(reply);
}

static uint32_t
read_u32(struct xpc_reader *reader)
{
	uint32_t value;
	memcpy(&value, reader->position, sizeof(value));
	reader->position += sizeof(value);
	return value;
}

static uint64_t
read_u64(struct xpc_reader *reader)
{
	uint64_t value;
	memcpy(&value, reader->position, sizeof(value));
	reader->position += sizeof(value);
	return value;
}

static const char *
read_key(struct xpc_reader *reader)
{
	const char *key = (const char *)reader->position;
	reader->position += strlen(key) + 1;
	reader_align(reader);
	return key;
}

static void
reader_align(struct xpc_reader *reader)
{
	while (((uintptr_t)reader->position & 3) != 0) {
		reader->position++;
	}
}

static void
begin_dictionary(struct xpc_builder *builder, uint32_t count)
{
	append_u32(builder, XPC_SERIAL_DICTIONARY);
	builder->dictionary_size_offset = builder->offset;
	append_u32(builder, 0);
	append_u32(builder, count);
}

static void
end_dictionary(struct xpc_builder *builder)
{
	uint32_t size = builder->offset - (builder->dictionary_size_offset + 4);
	memcpy(builder->buffer + builder->dictionary_size_offset, &size,
			sizeof(size));
}

static void
append_string(struct xpc_builder *builder, const char *key, const char *value)
{
	append_key(builder, key);
	append_u32(builder, XPC_SERIAL_STRING);
	uint32_t length = strlen(value) + 1;
	append_u32(builder, length);
	memcpy(builder->buffer + builder->offset, value, length);
	builder->offset += length;
	builder_align(builder);
}

static void
append_int64(struct xpc_builder *builder, const char *key, uint64_t value)
{
	append_key(builder, key);
	append_u32(builder, XPC_SERIAL_INT64);
	append_u64(builder, value);
}

static void
append_uuid(struct xpc_builder *builder, const char *key, const uint8_t *value)
{
	append_key(builder, key);
	append_u32(builder, XPC_SERIAL_UUID);
	memcpy(builder->buffer + builder->offset, value, 16);
	builder->offset += 16;
}

static void
append_key(struct xpc_builder *builder, const char *key)
{
	uint32_t length = strlen(key) + 1;
	memcpy(builder->buffer + builder->offset, key, length);
	builder->offset += length;
	builder_align(builder);
}

static void
append_u32(struct xpc_builder *builder, uint32_t value)
{
	memcpy(builder->buffer + builder->offset, &value, sizeof(value));
	builder->offset += sizeof(value);
}

static void
append_u64(struct xpc_builder *builder, uint64_t value)
{
	memcpy(builder->buffer + builder->offset, &value, sizeof(value));
	builder->offset += sizeof(value);
}

static void
builder_align(struct xpc_builder *builder)
{
	while ((builder->offset & 3) != 0) {
		builder->buffer[builder->offset++] = 0;
	}
}
