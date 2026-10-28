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

#include "osserialize.h"
#include <stdlib.h>
#include <string.h>

#define SIGNATURE      0x000000d3
#define END_COLLECTION 0x80000000
#define TYPE_SHIFT     24
#define TYPE_MASK      0x7f
#define LENGTH_MASK    0x00ffffff
#define OBJECT_REF     0x0c
#define MAX_DEPTH      64

struct parser {
	const uint32_t *words;
	size_t count;
	size_t position;

	struct os_object **objects;
	size_t object_count;
	size_t object_capacity;
	unsigned depth;
};

struct writer {
	uint32_t *words;
	size_t count;
	size_t capacity;
};

static struct os_object *parse_object(struct parser *parser, bool *end);
static struct os_object *parse_payload(
		struct parser *parser, uint32_t type, uint32_t length);
static bool parse_items(struct parser *parser, struct os_object *collection);
static struct os_object *parse_bytes(
		struct parser *parser, uint32_t type, uint32_t length);
static bool remember(struct parser *parser, struct os_object *object);
static struct os_object *object_create(enum os_type type);
static bool collection_append(
		struct os_object *collection, struct os_object *item);
static bool key_equals(const struct os_object *key, const char *name);
static void write_object(struct writer *writer, const struct os_object *object,
		bool last);
static void write_bytes(struct writer *writer, uint32_t header,
		const void *bytes, size_t size);
static void write_word(struct writer *writer, uint32_t word);

struct os_object *
os_unserialize(const void *buffer, size_t size)
{
	struct parser parser = {
			.words = buffer,
			.count = size / sizeof(uint32_t),
	};
	if (parser.count < 2 || parser.words[0] != SIGNATURE) {
		return NULL;
	}
	parser.position = 1;

	bool end;
	struct os_object *object = parse_object(&parser, &end);
	free(parser.objects);
	return object;
}

static struct os_object *
parse_object(struct parser *parser, bool *end)
{
	if (parser->position >= parser->count) {
		return NULL;
	}
	uint32_t header = parser->words[parser->position++];
	uint32_t type = (header >> TYPE_SHIFT) & TYPE_MASK;
	uint32_t length = header & LENGTH_MASK;
	*end = (header & END_COLLECTION) != 0;

	if (type == OBJECT_REF) {
		return (length < parser->object_count)
				? os_retain(parser->objects[length])
				: NULL;
	}

	struct os_object *object = parse_payload(parser, type, length);
	if (object == NULL) {
		return NULL;
	}
	if (!remember(parser, object)) {
		os_release(object);
		return NULL;
	}

	bool collection = type == OS_DICTIONARY || type == OS_ARRAY
			|| type == OS_SET;
	if (collection && length != 0 && !parse_items(parser, object)) {
		os_release(object);
		return NULL;
	}
	return object;
}

static struct os_object *
parse_payload(struct parser *parser, uint32_t type, uint32_t length)
{
	struct os_object *object;
	switch (type) {
	case OS_DICTIONARY:
	case OS_ARRAY:
	case OS_SET:
		return object_create(type);
	case OS_NUMBER:
		if (parser->count - parser->position < 2) {
			return NULL;
		}
		object = object_create(OS_NUMBER);
		object->number.value = parser->words[parser->position]
				| (uint64_t)parser->words[parser->position + 1]
						<< 32;
		object->number.bits = length;
		parser->position += 2;
		return object;
	case OS_SYMBOL:
	case OS_STRING:
	case OS_DATA:
		return parse_bytes(parser, type, length);
	case OS_BOOLEAN:
		object = object_create(OS_BOOLEAN);
		object->boolean = length != 0;
		return object;
	default:
		return NULL;
	}
}

static bool
parse_items(struct parser *parser, struct os_object *collection)
{
	if (++parser->depth > MAX_DEPTH) {
		return false;
	}
	bool end = false;
	while (!end) {
		struct os_object *item = parse_object(parser, &end);
		if (item == NULL || !collection_append(collection, item)) {
			if (item != NULL) {
				os_release(item);
			}
			return false;
		}
	}
	parser->depth--;
	return collection->type != OS_DICTIONARY
			|| collection->collection.count % 2 == 0;
}

static struct os_object *
parse_bytes(struct parser *parser, uint32_t type, uint32_t length)
{
	size_t words = ((size_t)length + 3) / 4;
	if (parser->count - parser->position < words) {
		return NULL;
	}
	const uint8_t *bytes
			= (const uint8_t *)&parser->words[parser->position];
	parser->position += words;

	size_t size = length;
	if (type == OS_SYMBOL) {
		size = strnlen((const char *)bytes, length);
	}

	struct os_object *object = object_create(type);
	object->data.bytes = malloc(size + 1);
	memcpy(object->data.bytes, bytes, size);
	object->data.bytes[size] = '\0';
	object->data.size = size;
	return object;
}

static bool
remember(struct parser *parser, struct os_object *object)
{
	if (parser->object_count == parser->object_capacity) {
		size_t capacity = parser->object_capacity * 2 + 16;
		struct os_object **objects = realloc(
				parser->objects, capacity * sizeof(*objects));
		if (objects == NULL) {
			return false;
		}
		parser->objects = objects;
		parser->object_capacity = capacity;
	}
	parser->objects[parser->object_count++] = object;
	return true;
}

void *
os_serialize(const struct os_object *object, size_t *size)
{
	struct writer writer = {0};
	write_word(&writer, SIGNATURE);
	write_object(&writer, object, true);
	*size = writer.count * sizeof(uint32_t);
	return writer.words;
}

static void
write_object(struct writer *writer, const struct os_object *object, bool last)
{
	uint32_t header = (uint32_t)object->type << TYPE_SHIFT
			| (last ? END_COLLECTION : 0);
	size_t count;
	switch (object->type) {
	case OS_DICTIONARY:
	case OS_ARRAY:
	case OS_SET:
		count = object->collection.count;
		write_word(writer,
				header
						| (uint32_t)(object->type == OS_DICTIONARY
										? count / 2
										: count));
		for (size_t i = 0; i < count; i++) {
			const struct os_object *item
					= object->collection.items[i];
			bool key = object->type == OS_DICTIONARY && i % 2 == 0;
			if (key) {

				write_bytes(writer,
						(uint32_t)OS_SYMBOL
								<< TYPE_SHIFT,
						item->data.bytes,
						item->data.size + 1);
			} else {
				write_object(writer, item, i == count - 1);
			}
		}
		break;
	case OS_NUMBER:
		write_word(writer, header | object->number.bits);
		write_word(writer, (uint32_t)object->number.value);
		write_word(writer, (uint32_t)(object->number.value >> 32));
		break;
	case OS_SYMBOL:
		write_bytes(writer, header, object->data.bytes,
				object->data.size + 1);
		break;
	case OS_STRING:
	case OS_DATA:
		write_bytes(writer, header, object->data.bytes,
				object->data.size);
		break;
	case OS_BOOLEAN:
		write_word(writer, header | (object->boolean ? 1 : 0));
		break;
	}
}

static void
write_bytes(struct writer *writer, uint32_t header, const void *bytes,
		size_t size)
{
	write_word(writer, header | (uint32_t)size);
	for (size_t i = 0; i < size; i += 4) {
		uint32_t word = 0;
		memcpy(&word, (const uint8_t *)bytes + i,
				size - i < 4 ? size - i : 4);
		write_word(writer, word);
	}
}

static void
write_word(struct writer *writer, uint32_t word)
{
	if (writer->count == writer->capacity) {
		writer->capacity = writer->capacity * 2 + 64;
		writer->words = realloc(writer->words,
				writer->capacity * sizeof(uint32_t));
	}
	writer->words[writer->count++] = word;
}

struct os_object *
os_retain(struct os_object *object)
{
	object->refs++;
	return object;
}

void
os_release(struct os_object *object)
{
	if (--object->refs != 0) {
		return;
	}
	switch (object->type) {
	case OS_DICTIONARY:
	case OS_ARRAY:
	case OS_SET:
		for (size_t i = 0; i < object->collection.count; i++) {
			os_release(object->collection.items[i]);
		}
		free(object->collection.items);
		break;
	case OS_SYMBOL:
	case OS_STRING:
	case OS_DATA:
		free(object->data.bytes);
		break;
	default:
		break;
	}
	free(object);
}

struct os_object *
os_dictionary_create(void)
{
	return object_create(OS_DICTIONARY);
}

struct os_object *
os_dictionary_get(const struct os_object *dictionary, const char *key)
{
	for (size_t i = 0; i + 1 < dictionary->collection.count; i += 2) {
		if (key_equals(dictionary->collection.items[i], key)) {
			return dictionary->collection.items[i + 1];
		}
	}
	return NULL;
}

void
os_dictionary_set(struct os_object *dictionary, const char *key,
		struct os_object *value)
{
	for (size_t i = 0; i + 1 < dictionary->collection.count; i += 2) {
		if (key_equals(dictionary->collection.items[i], key)) {
			os_release(dictionary->collection.items[i + 1]);
			dictionary->collection.items[i + 1] = value;
			return;
		}
	}
	collection_append(dictionary, os_symbol_create(key));
	collection_append(dictionary, value);
}

void
os_dictionary_remove(struct os_object *dictionary, const char *key)
{
	struct os_object **items = dictionary->collection.items;
	for (size_t i = 0; i + 1 < dictionary->collection.count; i += 2) {
		if (key_equals(items[i], key)) {
			os_release(items[i]);
			os_release(items[i + 1]);
			memmove(&items[i], &items[i + 2],
					(dictionary->collection.count - i - 2)
							* sizeof(*items));
			dictionary->collection.count -= 2;
			return;
		}
	}
}

struct os_object *
os_number_create(uint64_t value, uint32_t bits)
{
	struct os_object *object = object_create(OS_NUMBER);
	object->number.value = value;
	object->number.bits = bits;
	return object;
}

struct os_object *
os_boolean_create(bool value)
{
	struct os_object *object = object_create(OS_BOOLEAN);
	object->boolean = value;
	return object;
}

struct os_object *
os_symbol_create(const char *name)
{
	struct os_object *object = object_create(OS_SYMBOL);
	object->data.bytes = (uint8_t *)strdup(name);
	object->data.size = strlen(name);
	return object;
}

struct os_object *
os_string_create(const char *string)
{
	struct os_object *object = os_symbol_create(string);
	object->type = OS_STRING;
	return object;
}

struct os_object *
os_data_create(const void *bytes, size_t size)
{
	struct os_object *object = object_create(OS_DATA);
	object->data.bytes = malloc(size + 1);
	memcpy(object->data.bytes, bytes, size);
	object->data.bytes[size] = '\0';
	object->data.size = size;
	return object;
}

bool
os_number_value(const struct os_object *number, uint64_t *value)
{
	if (number == NULL || number->type != OS_NUMBER) {
		return false;
	}
	*value = number->number.value;
	return true;
}

static struct os_object *
object_create(enum os_type type)
{
	struct os_object *object = calloc(1, sizeof(*object));
	object->type = type;
	object->refs = 1;
	return object;
}

static bool
collection_append(struct os_object *collection, struct os_object *item)
{
	size_t count = collection->collection.count;
	struct os_object **items = realloc(collection->collection.items,
			(count + 1) * sizeof(*items));
	if (items == NULL) {
		return false;
	}
	items[count] = item;
	collection->collection.items = items;
	collection->collection.count = count + 1;
	return true;
}

static bool
key_equals(const struct os_object *key, const char *name)
{
	return (key->type == OS_SYMBOL || key->type == OS_STRING)
			&& strcmp((const char *)key->data.bytes, name) == 0;
}
