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
#include <mach/mach.h>
#include <mach/mig.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "bsd/kevent.h"
#include "ipc.h"

typedef enum {
	IPC_USER,
	IPC_KERNEL,
} ipc_side_t;

struct ipc_kmsg {
	struct ipc_kmsg *next;
	mach_msg_header_t header[];
};

struct ipc_port {
	mach_port_name_t name;
	ipc_kobject_type_t kotype;
	void *kobject;
	struct ipc_port *pset;
	struct ipc_kmsg *messages;
	struct ipc_kmsg **messages_tail;
	mach_port_seqno_t seqno;
	mach_port_context_t context;
};

struct ipc_entry {
	struct ipc_port *port;
	mach_port_type_t type;
	mach_port_urefs_t urefs;
	mach_port_urefs_t sorights;
	uint32_t generation;
};

struct task_subsystem;
struct mach_vm_subsystem;
struct mach_port_subsystem;
struct thread_act_subsystem;
struct mach_host_subsystem;
struct clock_subsystem;
struct task_restartable_subsystem;
struct host_priv_subsystem;
struct is_iokit_subsystem;

extern const struct task_subsystem task_subsystem;
extern const struct mach_vm_subsystem mach_vm_subsystem;
extern const struct mach_port_subsystem mach_port_subsystem;
extern const struct thread_act_subsystem thread_act_subsystem;
extern const struct mach_host_subsystem mach_host_subsystem;
extern const struct clock_subsystem clock_subsystem;
extern const struct task_restartable_subsystem task_restartable_subsystem;
extern const struct host_priv_subsystem host_priv_subsystem;
extern const struct is_iokit_subsystem is_iokit_subsystem;

static const struct mig_subsystem *const kobject_subsystems[] = {
		(const struct mig_subsystem *)&task_subsystem,
		(const struct mig_subsystem *)&mach_vm_subsystem,
		(const struct mig_subsystem *)&mach_port_subsystem,
		(const struct mig_subsystem *)&thread_act_subsystem,
		(const struct mig_subsystem *)&mach_host_subsystem,
		(const struct mig_subsystem *)&clock_subsystem,
		(const struct mig_subsystem *)&task_restartable_subsystem,
		(const struct mig_subsystem *)&host_priv_subsystem,
		(const struct mig_subsystem *)&is_iokit_subsystem,
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t arrival = PTHREAD_COND_INITIALIZER;
static struct ipc_entry *entries;
static uint32_t entry_count;
static struct ipc_port *kobjects[IPC_KOBJECT_SEMAPHORE + 1];

static mach_port_name_t kobject_send_right(ipc_kobject_type_t type);
static struct ipc_port *kobject_port(ipc_kobject_type_t type);
static mach_msg_return_t send(mach_msg_header_t *msg, mach_msg_size_t size,
		ipc_side_t sender);
static mach_msg_return_t copyin(mach_msg_header_t *header, ipc_side_t sender,
		struct ipc_port **dest);
static mach_msg_return_t copyin_body(mach_msg_header_t *header,
		ipc_side_t sender, ipc_side_t receiver);
static mach_msg_return_t transfer_right(mach_port_name_t name,
		mach_msg_type_name_t disposition, ipc_side_t sender,
		ipc_side_t receiver, mach_msg_type_name_t *type);
static bool has_right(
		struct ipc_entry *entry, mach_msg_type_name_t disposition);
static mach_msg_type_name_t received_type(mach_msg_type_name_t disposition);
static void *copy_ool(const void *address, mach_msg_size_t size);
static void enqueue(struct ipc_port *port, struct ipc_kmsg *kmsg);
static void release_unused_entries(mach_msg_header_t *header);
static void release_unused_entry(mach_port_name_t name);
static void unlock_and_notify_arrival(struct ipc_port *port);
static void serve_kobject(mach_msg_header_t *request);
static mach_msg_header_t *kobject_server(mach_msg_header_t *request);
static const struct mig_subsystem *kobject_subsystem(mach_msg_id_t id);
static mach_msg_return_t receive(mach_msg_header_t *msg,
		mach_msg_option64_t options, mach_msg_size_t rcv_size,
		mach_port_name_t rcv_name, mach_msg_timeout_t timeout);
static struct ipc_port *port_with_message(struct ipc_entry *entry);
static int wait_for_arrival(mach_msg_option64_t options,
		mach_msg_timeout_t timeout, struct timespec *deadline);
static void write_trailer(mach_msg_header_t *msg, struct ipc_port *port);
static void destroy_receive_right(struct ipc_entry *entry);
static struct ipc_entry *lookup(mach_port_name_t name);
static struct ipc_port *port_alloc(ipc_kobject_type_t kotype);
static struct ipc_entry *entry_alloc(struct ipc_port *port);
static void entry_release_if_unused(struct ipc_entry *entry);

mach_port_name_t
ipc_task_self(void)
{
	return kobject_send_right(IPC_KOBJECT_TASK);
}

mach_port_name_t
ipc_host_self(void)
{
	return kobject_send_right(IPC_KOBJECT_HOST);
}

mach_port_name_t
ipc_kobject_name(ipc_kobject_type_t type)
{
	pthread_mutex_lock(&lock);
	mach_port_name_t name = kobject_port(type)->name;
	pthread_mutex_unlock(&lock);
	return name;
}

mach_port_name_t
ipc_kobject_alloc(ipc_kobject_type_t type, void *kobject)
{
	pthread_mutex_lock(&lock);
	struct ipc_port *port = port_alloc(type);
	port->kobject = kobject;
	entry_alloc(port);
	pthread_mutex_unlock(&lock);
	return port->name;
}

mach_port_name_t
ipc_kobject_copy_send(mach_port_name_t name)
{
	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = lookup(name);
	entry->type |= MACH_PORT_TYPE_SEND;
	entry->urefs++;
	pthread_mutex_unlock(&lock);
	return name;
}

void *
ipc_kobject_lookup(mach_port_name_t name, ipc_kobject_type_t type)
{
	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = lookup(name);
	void *kobject = (entry != NULL && entry->port->kotype == type)
			? entry->port->kobject
			: NULL;
	pthread_mutex_unlock(&lock);
	return kobject;
}

void
ipc_kobject_destroy(mach_port_name_t name)
{
	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = lookup(name);
	entry->port->kotype = IPC_KOBJECT_NONE;
	entry->port->kobject = NULL;
	if (entry->type & MACH_PORT_TYPE_SEND) {
		entry->type = MACH_PORT_TYPE_DEAD_NAME;
	}
	entry_release_if_unused(entry);
	pthread_mutex_unlock(&lock);
}

bool
ipc_port_peek(mach_port_name_t name)
{
	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = lookup(name);
	bool pending = entry != NULL
			&& (entry->type
					& (MACH_PORT_TYPE_RECEIVE
							| MACH_PORT_TYPE_PORT_SET))
			&& port_with_message(entry) != NULL;
	pthread_mutex_unlock(&lock);
	return pending;
}

static mach_port_name_t
kobject_send_right(ipc_kobject_type_t type)
{
	pthread_mutex_lock(&lock);
	struct ipc_port *port = kobject_port(type);
	struct ipc_entry *entry = lookup(port->name);
	entry->type |= MACH_PORT_TYPE_SEND;
	entry->urefs++;
	pthread_mutex_unlock(&lock);
	return port->name;
}

static struct ipc_port *
kobject_port(ipc_kobject_type_t type)
{
	struct ipc_port **slot = &kobjects[type];
	if (*slot == NULL) {
		*slot = port_alloc(type);
	}
	if ((*slot)->name == MACH_PORT_NULL) {
		entry_alloc(*slot);
	}
	return *slot;
}

mach_msg_return_t
ipc_mach_msg(mach_msg_header_t *msg, mach_msg_option64_t options,
		mach_msg_size_t send_size, mach_msg_size_t rcv_size,
		mach_port_name_t rcv_name, mach_msg_timeout_t timeout)
{
	if (options & MACH64_SEND_MSG) {
		mach_msg_return_t mr = send(msg, send_size, IPC_USER);
		if (mr != MACH_MSG_SUCCESS) {
			return mr;
		}
	}

	if (options & MACH64_RCV_MSG) {
		return receive(msg, options, rcv_size, rcv_name, timeout);
	}

	return MACH_MSG_SUCCESS;
}

static mach_msg_return_t
send(mach_msg_header_t *msg, mach_msg_size_t size, ipc_side_t sender)
{
	struct ipc_kmsg *kmsg = malloc(
			sizeof(*kmsg) + size + sizeof(mach_msg_max_trailer_t));
	memcpy(kmsg->header, msg, size);
	kmsg->header->msgh_size = size;

	pthread_mutex_lock(&lock);
	struct ipc_port *dest;
	mach_msg_return_t mr = copyin(kmsg->header, sender, &dest);
	if (mr != MACH_MSG_SUCCESS) {
		release_unused_entries(kmsg->header);
		pthread_mutex_unlock(&lock);
		free(kmsg);
		return mr;
	}

	if (dest->kotype == IPC_KOBJECT_NONE) {
		enqueue(dest, kmsg);
		release_unused_entries(kmsg->header);
		unlock_and_notify_arrival(dest);
		return MACH_MSG_SUCCESS;
	}

	write_trailer(kmsg->header, dest);
	pthread_mutex_unlock(&lock);

	serve_kobject(kmsg->header);

	pthread_mutex_lock(&lock);
	release_unused_entries(kmsg->header);
	pthread_mutex_unlock(&lock);

	free(kmsg);
	return MACH_MSG_SUCCESS;
}

static mach_msg_return_t
copyin(mach_msg_header_t *header, ipc_side_t sender, struct ipc_port **dest)
{
	mach_msg_bits_t bits = header->msgh_bits;

	struct ipc_entry *dest_entry = lookup(header->msgh_remote_port);
	if (dest_entry == NULL || (dest_entry->type & MACH_PORT_TYPE_PORT_SET)
			|| (dest_entry->type & MACH_PORT_TYPE_DEAD_NAME)) {
		return MACH_SEND_INVALID_DEST;
	}
	*dest = dest_entry->port;
	ipc_side_t receiver = ((*dest)->kotype == IPC_KOBJECT_NONE)
			? IPC_USER
			: IPC_KERNEL;

	mach_msg_type_name_t dest_type;
	if (transfer_right(header->msgh_remote_port,
			    MACH_MSGH_BITS_REMOTE(bits), sender, IPC_KERNEL,
			    &dest_type)
			!= MACH_MSG_SUCCESS) {
		return MACH_SEND_INVALID_DEST;
	}

	mach_msg_type_name_t reply_type;
	if (transfer_right(header->msgh_local_port, MACH_MSGH_BITS_LOCAL(bits),
			    sender, receiver, &reply_type)
			!= MACH_MSG_SUCCESS) {
		return MACH_SEND_INVALID_REPLY;
	}

	header->msgh_bits = MACH_MSGH_BITS_SET(reply_type, dest_type, 0,
			bits & MACH_MSGH_BITS_COMPLEX);
	header->msgh_remote_port = header->msgh_local_port;
	header->msgh_local_port = (*dest)->name;
	header->msgh_voucher_port = MACH_PORT_NULL;

	if (bits & MACH_MSGH_BITS_COMPLEX) {
		return copyin_body(header, sender, receiver);
	}
	return MACH_MSG_SUCCESS;
}

static mach_msg_return_t
copyin_body(mach_msg_header_t *header, ipc_side_t sender, ipc_side_t receiver)
{
	mach_msg_body_t *body = (mach_msg_body_t *)(header + 1);
	uint8_t *cursor = (uint8_t *)(body + 1);

	for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count; i++) {
		mach_msg_type_descriptor_t *descriptor
				= (mach_msg_type_descriptor_t *)cursor;
		switch (descriptor->type) {
		case MACH_MSG_PORT_DESCRIPTOR: {
			mach_msg_port_descriptor_t *d
					= (mach_msg_port_descriptor_t *)cursor;
			mach_msg_type_name_t type;
			if (transfer_right(d->name, d->disposition, sender,
					    receiver, &type)
					!= MACH_MSG_SUCCESS) {
				return MACH_SEND_INVALID_RIGHT;
			}
			d->disposition = type;
			cursor += sizeof(*d);
		} break;
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR: {
			mach_msg_guarded_port_descriptor64_t *d
					= (mach_msg_guarded_port_descriptor64_t
									*)
							cursor;
			mach_msg_type_name_t type;
			if (transfer_right(d->name, d->disposition, sender,
					    receiver, &type)
					!= MACH_MSG_SUCCESS) {
				return MACH_SEND_INVALID_RIGHT;
			}
			d->disposition = type;
			cursor += sizeof(*d);
		} break;
		case MACH_MSG_OOL_DESCRIPTOR:
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR: {
			mach_msg_ool_descriptor64_t *d
					= (mach_msg_ool_descriptor64_t *)cursor;
			if (sender == IPC_USER && receiver == IPC_USER
					&& !d->deallocate) {
				d->address = (uint64_t)copy_ool(
						(void *)d->address, d->size);
			}
			cursor += sizeof(*d);
		} break;
		case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
			mach_msg_ool_ports_descriptor64_t *d
					= (mach_msg_ool_ports_descriptor64_t *)
							cursor;
			mach_port_name_t *names
					= (mach_port_name_t *)d->address;
			mach_msg_type_name_t type
					= received_type(d->disposition);
			for (mach_msg_size_t j = 0; j < d->count; j++) {
				if (transfer_right(names[j], d->disposition,
						    sender, receiver, &type)
						!= MACH_MSG_SUCCESS) {
					return MACH_SEND_INVALID_RIGHT;
				}
			}
			if (sender == IPC_USER && receiver == IPC_USER
					&& !d->deallocate) {
				d->address = (uint64_t)copy_ool(names,
						d->count * sizeof(*names));
			}
			d->disposition = type;
			cursor += sizeof(*d);
		} break;
		default:
			return MACH_SEND_INVALID_TYPE;
		}
	}

	return MACH_MSG_SUCCESS;
}

static mach_msg_return_t
transfer_right(mach_port_name_t name, mach_msg_type_name_t disposition,
		ipc_side_t sender, ipc_side_t receiver,
		mach_msg_type_name_t *type)
{
	*type = received_type(disposition);
	if (!MACH_PORT_VALID(name)) {
		return MACH_MSG_SUCCESS;
	}

	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		return MACH_SEND_INVALID_RIGHT;
	}

	if (sender == IPC_USER) {
		if (!has_right(entry, disposition)) {
			return MACH_SEND_INVALID_RIGHT;
		}
		if (receiver == IPC_KERNEL) {
			switch (disposition) {
			case MACH_MSG_TYPE_MOVE_SEND:
				if (--entry->urefs == 0) {
					entry->type &= ~MACH_PORT_TYPE_SEND;
				}
				break;
			case MACH_MSG_TYPE_MOVE_SEND_ONCE:
				if (--entry->sorights == 0) {
					entry->type &= ~MACH_PORT_TYPE_SEND_ONCE;
				}
				break;
			case MACH_MSG_TYPE_MOVE_RECEIVE:
				unimplemented();
			}
			return MACH_MSG_SUCCESS;
		}
	}

	if (receiver == IPC_USER) {
		bool created = sender == IPC_KERNEL
				|| (disposition != MACH_MSG_TYPE_MOVE_SEND
						&& disposition != MACH_MSG_TYPE_MOVE_SEND_ONCE
						&& disposition != MACH_MSG_TYPE_MOVE_RECEIVE);
		if (created) {
			switch (*type) {
			case MACH_MSG_TYPE_PORT_SEND:
				entry->type |= MACH_PORT_TYPE_SEND;
				entry->urefs++;
				break;
			case MACH_MSG_TYPE_PORT_SEND_ONCE:
				entry->type |= MACH_PORT_TYPE_SEND_ONCE;
				entry->sorights++;
				break;
			default:
				unimplemented();
			}
		}
	}

	return MACH_MSG_SUCCESS;
}

static bool
has_right(struct ipc_entry *entry, mach_msg_type_name_t disposition)
{
	switch (disposition) {
	case MACH_MSG_TYPE_MOVE_RECEIVE:
	case MACH_MSG_TYPE_MAKE_SEND:
	case MACH_MSG_TYPE_MAKE_SEND_ONCE:
		return entry->type & MACH_PORT_TYPE_RECEIVE;
	case MACH_MSG_TYPE_MOVE_SEND:
	case MACH_MSG_TYPE_COPY_SEND:
		return entry->type & MACH_PORT_TYPE_SEND;
	case MACH_MSG_TYPE_MOVE_SEND_ONCE:
		return entry->type & MACH_PORT_TYPE_SEND_ONCE;
	default:
		return false;
	}
}

static mach_msg_type_name_t
received_type(mach_msg_type_name_t disposition)
{
	switch (disposition) {
	case MACH_MSG_TYPE_MOVE_RECEIVE:
		return MACH_MSG_TYPE_PORT_RECEIVE;
	case MACH_MSG_TYPE_MOVE_SEND:
	case MACH_MSG_TYPE_COPY_SEND:
	case MACH_MSG_TYPE_MAKE_SEND:
		return MACH_MSG_TYPE_PORT_SEND;
	case MACH_MSG_TYPE_MOVE_SEND_ONCE:
	case MACH_MSG_TYPE_MAKE_SEND_ONCE:
		return MACH_MSG_TYPE_PORT_SEND_ONCE;
	default:
		return MACH_MSG_TYPE_PORT_NONE;
	}
}

static void *
copy_ool(const void *address, mach_msg_size_t size)
{
	if (size == 0) {
		return NULL;
	}
	void *copy = mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON, -1, 0);
	memcpy(copy, address, size);
	return copy;
}

static void
enqueue(struct ipc_port *port, struct ipc_kmsg *kmsg)
{
	kmsg->next = NULL;
	if (port->messages == NULL) {
		port->messages_tail = &port->messages;
	}
	*port->messages_tail = kmsg;
	port->messages_tail = &kmsg->next;
	pthread_cond_broadcast(&arrival);
}

static void
release_unused_entries(mach_msg_header_t *header)
{
	release_unused_entry(header->msgh_remote_port);
	release_unused_entry(header->msgh_local_port);
	if (!(header->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
		return;
	}

	mach_msg_body_t *body = (mach_msg_body_t *)(header + 1);
	uint8_t *cursor = (uint8_t *)(body + 1);
	for (mach_msg_size_t i = 0; i < body->msgh_descriptor_count; i++) {
		mach_msg_type_descriptor_t *descriptor
				= (mach_msg_type_descriptor_t *)cursor;
		switch (descriptor->type) {
		case MACH_MSG_PORT_DESCRIPTOR: {
			mach_msg_port_descriptor_t *d
					= (mach_msg_port_descriptor_t *)cursor;
			release_unused_entry(d->name);
			cursor += sizeof(*d);
		} break;
		case MACH_MSG_GUARDED_PORT_DESCRIPTOR: {
			mach_msg_guarded_port_descriptor64_t *d
					= (mach_msg_guarded_port_descriptor64_t
									*)
							cursor;
			release_unused_entry(d->name);
			cursor += sizeof(*d);
		} break;
		case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
			mach_msg_ool_ports_descriptor64_t *d
					= (mach_msg_ool_ports_descriptor64_t *)
							cursor;
			mach_port_name_t *names
					= (mach_port_name_t *)d->address;
			for (mach_msg_size_t j = 0; j < d->count; j++) {
				release_unused_entry(names[j]);
			}
			cursor += sizeof(*d);
		} break;
		default:
			cursor += sizeof(mach_msg_ool_descriptor64_t);
		}
	}
}

static void
release_unused_entry(mach_port_name_t name)
{
	struct ipc_entry *entry = lookup(name);
	if (entry != NULL) {
		entry_release_if_unused(entry);
	}
}

static void
unlock_and_notify_arrival(struct ipc_port *port)
{
	mach_port_name_t name = port->name;
	mach_port_name_t pset = (port->pset != NULL) ? port->pset->name
						     : MACH_PORT_NULL;
	pthread_mutex_unlock(&lock);

	kevent_machport_arrival(name);
	if (pset != MACH_PORT_NULL) {
		kevent_machport_arrival(pset);
	}
}

static void
serve_kobject(mach_msg_header_t *request)
{
	mach_msg_header_t *reply = kobject_server(request);
	if (reply == NULL) {
		return;
	}

	if (reply->msgh_remote_port != MACH_PORT_NULL) {
		send(reply, reply->msgh_size, IPC_KERNEL);
	}
	free(reply);
}

static mach_msg_header_t *
kobject_server(mach_msg_header_t *request)
{
	mach_msg_id_t id = request->msgh_id;
	const struct mig_subsystem *subsystem = kobject_subsystem(id);
	mig_stub_routine_t routine = (subsystem != NULL)
			? subsystem->routine[id - subsystem->start].stub_routine
			: NULL;
	mach_msg_size_t size = (subsystem != NULL) ? subsystem->maxsize
						   : sizeof(mig_reply_error_t);

	mig_reply_error_t *reply = calloc(1, size);
	reply->Head.msgh_bits = MACH_MSGH_BITS(
			MACH_MSGH_BITS_REMOTE(request->msgh_bits), 0);
	reply->Head.msgh_size = sizeof(*reply);
	reply->Head.msgh_remote_port = request->msgh_remote_port;
	reply->Head.msgh_id = id + 100;
	reply->NDR = NDR_record;

	if (routine == NULL) {
#ifdef ENABLE_STRACE
		fprintf(stderr, ">> Unknown kernel object message ID: %d\n",
				id);
#endif
		reply->RetCode = MIG_BAD_ID;
	} else {
		routine(request, &reply->Head);
	}

	if (!(reply->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX)
			&& reply->RetCode == MIG_NO_REPLY) {
		free(reply);
		return NULL;
	}
	return &reply->Head;
}

static const struct mig_subsystem *
kobject_subsystem(mach_msg_id_t id)
{
	uint32_t count = sizeof(kobject_subsystems)
			/ sizeof(kobject_subsystems[0]);
	for (uint32_t i = 0; i < count; i++) {
		const struct mig_subsystem *subsystem = kobject_subsystems[i];
		if (id >= subsystem->start && id < subsystem->end) {
			return subsystem;
		}
	}
	return NULL;
}

static mach_msg_return_t
receive(mach_msg_header_t *msg, mach_msg_option64_t options,
		mach_msg_size_t rcv_size, mach_port_name_t rcv_name,
		mach_msg_timeout_t timeout)
{
	pthread_mutex_lock(&lock);

	struct timespec deadline = {0, 0};
	struct ipc_port *port;
	bool waited = false;
	while (true) {
		struct ipc_entry *entry = lookup(rcv_name);
		if (entry == NULL
				|| !(entry->type
						& (MACH_PORT_TYPE_RECEIVE
								| MACH_PORT_TYPE_PORT_SET))) {
			pthread_mutex_unlock(&lock);
			return waited ? MACH_RCV_PORT_DIED
				      : MACH_RCV_INVALID_NAME;
		}

		port = port_with_message(entry);
		if (port != NULL) {
			break;
		}

		if (wait_for_arrival(options, timeout, &deadline)
				== ETIMEDOUT) {
			pthread_mutex_unlock(&lock);
			return MACH_RCV_TIMED_OUT;
		}
		waited = true;
	}

	struct ipc_kmsg *kmsg = port->messages;
	mach_msg_size_t size = kmsg->header->msgh_size;
	mach_msg_size_t trailer_size
			= REQUESTED_TRAILER_SIZE((mach_msg_option_t)options);
	if (size + trailer_size > rcv_size && (options & MACH_RCV_LARGE)) {
		msg->msgh_size = size + trailer_size;
		pthread_mutex_unlock(&lock);
		return MACH_RCV_TOO_LARGE;
	}

	port->messages = kmsg->next;
	write_trailer(kmsg->header, port);
	pthread_mutex_unlock(&lock);

	mach_msg_return_t mr = MACH_RCV_TOO_LARGE;
	if (size + trailer_size <= rcv_size) {
		memcpy(msg, kmsg->header, size);
		mach_msg_max_trailer_t *trailer
				= (mach_msg_max_trailer_t *)((uint8_t *)msg
						+ size);
		memcpy(trailer, (uint8_t *)kmsg->header + size, trailer_size);
		trailer->msgh_trailer_size = trailer_size;
		mr = MACH_MSG_SUCCESS;
	}
	free(kmsg);
	return mr;
}

static struct ipc_port *
port_with_message(struct ipc_entry *entry)
{
	if (entry->type & MACH_PORT_TYPE_RECEIVE) {
		return (entry->port->messages != NULL) ? entry->port : NULL;
	}

	for (uint32_t i = 1; i < entry_count; i++) {
		struct ipc_port *member = entries[i].port;
		if (member != NULL && member->pset == entry->port
				&& member->messages != NULL) {
			return member;
		}
	}
	return NULL;
}

static int
wait_for_arrival(mach_msg_option64_t options, mach_msg_timeout_t timeout,
		struct timespec *deadline)
{
	if (!(options & MACH_RCV_TIMEOUT)) {
		return pthread_cond_wait(&arrival, &lock);
	}

	if (timeout == 0) {
		return ETIMEDOUT;
	}

	if (deadline->tv_sec == 0) {
		clock_gettime(CLOCK_REALTIME, deadline);
		deadline->tv_sec += timeout / 1000;
		deadline->tv_nsec += (timeout % 1000) * 1000000;
		if (deadline->tv_nsec >= 1000000000) {
			deadline->tv_sec++;
			deadline->tv_nsec -= 1000000000;
		}
	}
	return pthread_cond_timedwait(&arrival, &lock, deadline);
}

static void
write_trailer(mach_msg_header_t *msg, struct ipc_port *port)
{
	mach_msg_max_trailer_t *trailer
			= (mach_msg_max_trailer_t *)((uint8_t *)msg
					+ msg->msgh_size);
	memset(trailer, 0, sizeof(*trailer));
	trailer->msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0;
	trailer->msgh_trailer_size = sizeof(*trailer);
	trailer->msgh_seqno = port->seqno++;
	trailer->msgh_sender.val[0] = geteuid();
	trailer->msgh_sender.val[1] = getegid();
	trailer->msgh_audit.val[1] = geteuid();
	trailer->msgh_audit.val[2] = getegid();
	trailer->msgh_audit.val[3] = getuid();
	trailer->msgh_audit.val[4] = getgid();
	trailer->msgh_audit.val[5] = getpid();
	trailer->msgh_context = port->context;
}

mach_msg_return_t
ipc_kernel_send(mach_msg_header_t *msg)
{
	return send(msg, msg->msgh_size, IPC_KERNEL);
}

kern_return_t
ipc_port_allocate(mach_port_right_t right, mach_port_name_t *name)
{
	mach_port_type_t type;
	switch (right) {
	case MACH_PORT_RIGHT_RECEIVE:
		type = MACH_PORT_TYPE_RECEIVE;
		break;
	case MACH_PORT_RIGHT_PORT_SET:
		type = MACH_PORT_TYPE_PORT_SET;
		break;
	default:
		unimplemented();
	}

	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = entry_alloc(port_alloc(IPC_KOBJECT_NONE));
	entry->type = type;
	*name = entry->port->name;
	pthread_mutex_unlock(&lock);
	return KERN_SUCCESS;
}

kern_return_t
ipc_port_construct(mach_port_options_t *options, mach_port_context_t context,
		mach_port_name_t *name)
{
	pthread_mutex_lock(&lock);
	struct ipc_entry *entry = entry_alloc(port_alloc(IPC_KOBJECT_NONE));
	entry->type = MACH_PORT_TYPE_RECEIVE;
	entry->port->context = context;
	if (options->flags & MPO_INSERT_SEND_RIGHT) {
		entry->type |= MACH_PORT_TYPE_SEND;
		entry->urefs = 1;
	}
	*name = entry->port->name;
	pthread_mutex_unlock(&lock);
	return KERN_SUCCESS;
}

kern_return_t
ipc_port_destruct(mach_port_name_t name, mach_port_delta_t srdelta,
		mach_port_context_t guard)
{
	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else if (!(entry->type & MACH_PORT_TYPE_RECEIVE)) {
		kr = KERN_INVALID_RIGHT;
	} else {
		entry->urefs += srdelta;
		if (entry->urefs == 0) {
			entry->type &= ~MACH_PORT_TYPE_SEND;
		}
		destroy_receive_right(entry);
		entry_release_if_unused(entry);
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_deallocate(mach_port_name_t name)
{
	if (!MACH_PORT_VALID(name)) {
		return KERN_SUCCESS;
	}

	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else if (entry->type
			& (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_DEAD_NAME)) {
		if (--entry->urefs == 0) {
			entry->type &= ~(MACH_PORT_TYPE_SEND
					| MACH_PORT_TYPE_DEAD_NAME);
		}
	} else if (entry->type & MACH_PORT_TYPE_SEND_ONCE) {
		if (--entry->sorights == 0) {
			entry->type &= ~MACH_PORT_TYPE_SEND_ONCE;
		}
	} else {
		kr = KERN_INVALID_RIGHT;
	}
	if (entry != NULL) {
		entry_release_if_unused(entry);
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_mod_refs(mach_port_name_t name, mach_port_right_t right,
		mach_port_delta_t delta)
{
	if (!MACH_PORT_VALID(name)) {
		return (right == MACH_PORT_RIGHT_SEND
				       || right == MACH_PORT_RIGHT_SEND_ONCE)
				? KERN_SUCCESS
				: KERN_INVALID_NAME;
	}

	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
		goto out;
	}

	switch (right) {
	case MACH_PORT_RIGHT_SEND:
	case MACH_PORT_RIGHT_DEAD_NAME: {
		mach_port_type_t type = MACH_PORT_TYPE(right);
		if (!(entry->type & type)) {
			kr = KERN_INVALID_RIGHT;
			break;
		}
		entry->urefs += delta;
		if (entry->urefs == 0) {
			entry->type &= ~type;
		}
	} break;
	case MACH_PORT_RIGHT_SEND_ONCE:
		if (!(entry->type & MACH_PORT_TYPE_SEND_ONCE)) {
			kr = KERN_INVALID_RIGHT;
			break;
		}
		entry->sorights += delta;
		if (entry->sorights == 0) {
			entry->type &= ~MACH_PORT_TYPE_SEND_ONCE;
		}
		break;
	case MACH_PORT_RIGHT_RECEIVE:
		if (!(entry->type & MACH_PORT_TYPE_RECEIVE)) {
			kr = KERN_INVALID_RIGHT;
		} else if (delta < 0) {
			destroy_receive_right(entry);
		}
		break;
	case MACH_PORT_RIGHT_PORT_SET:
		if (!(entry->type & MACH_PORT_TYPE_PORT_SET)) {
			kr = KERN_INVALID_RIGHT;
		} else if (delta < 0) {
			entry->type &= ~MACH_PORT_TYPE_PORT_SET;
		}
		break;
	default:
		kr = KERN_INVALID_VALUE;
	}
	entry_release_if_unused(entry);
out:
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_insert_right(mach_port_name_t name, mach_port_name_t poly,
		mach_msg_type_name_t poly_poly)
{
	if (name != poly) {
		unimplemented();
	}

	pthread_mutex_lock(&lock);
	mach_msg_type_name_t type;
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else if (!has_right(entry, poly_poly)) {
		kr = KERN_INVALID_RIGHT;
	} else if (poly_poly != MACH_MSG_TYPE_MOVE_SEND
			&& poly_poly != MACH_MSG_TYPE_MOVE_SEND_ONCE) {
		transfer_right(name, poly_poly, IPC_KERNEL, IPC_USER, &type);
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_type(mach_port_name_t name, mach_port_type_t *type)
{
	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else {
		*type = entry->type;
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_get_refs(mach_port_name_t name, mach_port_right_t right,
		mach_port_urefs_t *refs)
{
	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else {
		switch (right) {
		case MACH_PORT_RIGHT_SEND:
		case MACH_PORT_RIGHT_DEAD_NAME:
			*refs = (entry->type & MACH_PORT_TYPE(right))
					? entry->urefs
					: 0;
			break;
		case MACH_PORT_RIGHT_SEND_ONCE:
			*refs = entry->sorights;
			break;
		default:
			*refs = (entry->type & MACH_PORT_TYPE(right)) ? 1 : 0;
		}
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_get_context(mach_port_name_t name, mach_port_context_t *context)
{
	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else if (!(entry->type & MACH_PORT_TYPE_RECEIVE)) {
		kr = KERN_INVALID_RIGHT;
	} else {
		*context = entry->port->context;
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_set_context(mach_port_name_t name, mach_port_context_t context)
{
	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else if (!(entry->type & MACH_PORT_TYPE_RECEIVE)) {
		kr = KERN_INVALID_RIGHT;
	} else {
		entry->port->context = context;
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_move_member(mach_port_name_t member, mach_port_name_t pset)
{
	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *member_entry = lookup(member);
	struct ipc_entry *pset_entry = lookup(pset);
	if (member_entry == NULL
			|| (pset != MACH_PORT_NULL && pset_entry == NULL)) {
		kr = KERN_INVALID_NAME;
	} else if (!(member_entry->type & MACH_PORT_TYPE_RECEIVE)
			|| (pset_entry != NULL
					&& !(pset_entry->type
							& MACH_PORT_TYPE_PORT_SET))) {
		kr = KERN_INVALID_RIGHT;
	} else {
		member_entry->port->pset = (pset_entry != NULL)
				? pset_entry->port
				: NULL;
		pthread_cond_broadcast(&arrival);
		if (pset_entry != NULL
				&& member_entry->port->messages != NULL) {
			unlock_and_notify_arrival(member_entry->port);
			return kr;
		}
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

kern_return_t
ipc_port_get_status(mach_port_name_t name, mach_port_status_t *status)
{
	pthread_mutex_lock(&lock);
	kern_return_t kr = KERN_SUCCESS;
	struct ipc_entry *entry = lookup(name);
	if (entry == NULL) {
		kr = KERN_INVALID_NAME;
	} else if (!(entry->type & MACH_PORT_TYPE_RECEIVE)) {
		kr = KERN_INVALID_RIGHT;
	} else {
		struct ipc_port *port = entry->port;
		memset(status, 0, sizeof(*status));
		status->mps_pset = (port->pset != NULL) ? port->pset->name
							: MACH_PORT_NULL;
		status->mps_seqno = port->seqno;
		status->mps_qlimit = MACH_PORT_QLIMIT_DEFAULT;
		for (struct ipc_kmsg *kmsg = port->messages; kmsg != NULL;
				kmsg = kmsg->next) {
			status->mps_msgcount++;
		}
		status->mps_sorights = entry->sorights;
		status->mps_srights = (entry->type & MACH_PORT_TYPE_SEND) != 0;
	}
	pthread_mutex_unlock(&lock);
	return kr;
}

static void
destroy_receive_right(struct ipc_entry *entry)
{
	struct ipc_port *port = entry->port;
	while (port->messages != NULL) {
		struct ipc_kmsg *kmsg = port->messages;
		port->messages = kmsg->next;
		free(kmsg);
	}

	entry->type &= ~MACH_PORT_TYPE_RECEIVE;
	if (entry->type & MACH_PORT_TYPE_SEND) {
		entry->type = MACH_PORT_TYPE_DEAD_NAME;
	}
	pthread_cond_broadcast(&arrival);
}

static struct ipc_entry *
lookup(mach_port_name_t name)
{
	uint32_t index = MACH_PORT_INDEX(name);
	if (index == 0 || index >= entry_count) {
		return NULL;
	}

	struct ipc_entry *entry = &entries[index];
	if (entry->port == NULL || MACH_PORT_GEN(name) != entry->generation) {
		return NULL;
	}
	return entry;
}

static struct ipc_port *
port_alloc(ipc_kobject_type_t kotype)
{
	struct ipc_port *port = calloc(1, sizeof(*port));
	port->kotype = kotype;
	return port;
}

static struct ipc_entry *
entry_alloc(struct ipc_port *port)
{
	uint32_t index;
	for (index = 1; index < entry_count; index++) {
		if (entries[index].port == NULL) {
			break;
		}
	}

	if (index >= entry_count) {
		uint32_t count = (entry_count != 0) ? entry_count * 2 : 64;
		entries = realloc(entries, count * sizeof(*entries));
		memset(&entries[entry_count], 0,
				(count - entry_count) * sizeof(*entries));
		for (uint32_t i = entry_count; i < count; i++) {
			entries[i].generation = MACH_PORT_GEN(3);
		}
		entry_count = count;
	}

	struct ipc_entry *entry = &entries[index];
	entry->port = port;
	port->name = MACH_PORT_MAKE(index, entry->generation);
	return entry;
}

static void
entry_release_if_unused(struct ipc_entry *entry)
{
	if (entry->type != 0) {
		return;
	}

	struct ipc_port *port = entry->port;
	port->name = MACH_PORT_NULL;
	if (port->kotype == IPC_KOBJECT_NONE) {
		free(port);
	}
	entry->port = NULL;
	entry->urefs = 0;
	entry->sorights = 0;
	entry->generation += MACH_PORT_GEN(4);
}
