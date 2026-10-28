/*
 * Copyright © 2026 Håvard Sørbø
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

enum os_type {
	OS_DICTIONARY = 0x01,
	OS_ARRAY = 0x02,
	OS_SET = 0x03,
	OS_NUMBER = 0x04,
	OS_SYMBOL = 0x08,
	OS_STRING = 0x09,
	OS_DATA = 0x0a,
	OS_BOOLEAN = 0x0b,
};

struct os_object {
	enum os_type type;
	unsigned refs;
	union {
		struct {
			uint64_t value;
			uint32_t bits;
		} number;
		bool boolean;

		struct {
			uint8_t *bytes;
			size_t size;
		} data;

		struct {
			struct os_object **items;
			size_t count;
		} collection;
	};
};

struct os_object *os_unserialize(const void *buffer, size_t size);
void *os_serialize(const struct os_object *object, size_t *size);

struct os_object *os_retain(struct os_object *object);
void os_release(struct os_object *object);

struct os_object *os_dictionary_create(void);
struct os_object *os_dictionary_get(
		const struct os_object *dictionary, const char *key);
void os_dictionary_set(struct os_object *dictionary, const char *key,
		struct os_object *value);
void os_dictionary_remove(struct os_object *dictionary, const char *key);
struct os_object *os_number_create(uint64_t value, uint32_t bits);
struct os_object *os_boolean_create(bool value);
struct os_object *os_symbol_create(const char *name);
struct os_object *os_string_create(const char *string);
struct os_object *os_data_create(const void *bytes, size_t size);
bool os_number_value(const struct os_object *number, uint64_t *value);
