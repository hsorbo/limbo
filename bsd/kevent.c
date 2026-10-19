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
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "handler.h"
#include "kevent.h"
#include "osfmk/ipc.h"
#include "workq.h"
#include "xnu-errno.h"

#define EVFILT_MACHPORT -8
#define EVFILT_TIMER    -7
#define EVFILT_USER     -10
#define EVFILT_WORKLOOP -17

#define EV_ADD            0x0001
#define EV_DELETE         0x0002
#define EV_ENABLE         0x0004
#define EV_DISABLE        0x0008
#define EV_ONESHOT        0x0010
#define EV_CLEAR          0x0020
#define EV_RECEIPT        0x0040
#define EV_DISPATCH       0x0080
#define EV_UDATA_SPECIFIC 0x0100
#define EV_VANISHED       0x0200
#define EV_ERROR          0x4000

#define KEVENT_FLAG_IMMEDIATE                 0x000001
#define KEVENT_FLAG_ERROR_EVENTS              0x000002
#define KEVENT_FLAG_WORKQ                     0x000020
#define KEVENT_FLAG_WORKQ_MANAGER             0x000200
#define KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST     0x020000
#define KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST 0x040000

#define NOTE_TRIGGER    0x01000000
#define NOTE_FFAND      0x40000000
#define NOTE_FFOR       0x80000000
#define NOTE_FFCOPY     0xc0000000
#define NOTE_FFCTRLMASK 0xc0000000
#define NOTE_FFLAGSMASK 0x00ffffff

#define NOTE_SECONDS  0x00000001
#define NOTE_USECONDS 0x00000002
#define NOTE_NSECONDS 0x00000004
#define NOTE_ABSOLUTE 0x00000008
#define NOTE_MACHTIME 0x00000100

#define NOTE_WL_THREAD_REQUEST 0x00000001
#define NOTE_WL_SYNC_WAIT      0x00000004
#define NOTE_WL_SYNC_WAKE      0x00000008
#define NOTE_WL_COMMANDS_MASK  0x8000000f
#define NOTE_WL_END_OWNERSHIP  0x00000020
#define NOTE_WL_IGNORE_ESTALE  0x00000100

#define EV_EXTIDX_WL_ADDR  1
#define EV_EXTIDX_WL_MASK  2
#define EV_EXTIDX_WL_VALUE 3

#define PTHREAD_PRIORITY_EVENT_MANAGER_FLAG 0x02000000
#define PTHREAD_PRIORITY_QOS_CLASS_MASK     0x003fff00
#define PTHREAD_PRIORITY_QOS_CLASS_SHIFT    8

#define THREAD_QOS_LEGACY 4

typedef enum {
	KQUEUE_WORKQ,
	KQUEUE_WORKLOOP,
} kqueue_kind_t;

struct knote {
	struct knote *next;
	struct kqueue *kq;
	struct kevent_qos_s kev;
	bool active;
	bool disabled;
	bool manager;
	bool woken;
	uint64_t deadline;
	uint64_t interval;
};

struct kqueue {
	struct kqueue *next;
	kqueue_kind_t kind;
	uint64_t id;
	struct knote *knotes;
	bool bound[2];
	bool requested[2];
	bool owned;
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct kqueue workq_kqueue = {.kind = KQUEUE_WORKQ};
static struct kqueue *workloops;

static pthread_cond_t sync_wakeup = PTHREAD_COND_INITIALIZER;
static pthread_cond_t timer_wakeup;
static bool timer_thread_started;

static struct kqueue *workloop_lookup(uint64_t id, unsigned int flags);
static int kevent_internal(struct kqueue *kq,
		const struct kevent_qos_s *changes, int nchanges,
		struct kevent_qos_s *events, int nevents, uint8_t *data_out,
		size_t *data_available, unsigned int flags);
static int kevent_register(
		struct kqueue *kq, const struct kevent_qos_s *change);
static struct knote *knote_find(
		struct kqueue *kq, const struct kevent_qos_s *change);
static struct knote *knote_attach(
		struct kqueue *kq, const struct kevent_qos_s *change);
static void knote_detach(struct knote *kn);
static int knote_touch(struct knote *kn, const struct kevent_qos_s *change);
static void user_touch(struct knote *kn, const struct kevent_qos_s *change);
static void timer_arm(struct knote *kn);
static uint64_t timer_nanoseconds(uint32_t fflags, int64_t data);
static uint64_t now_monotonic(void);
static uint64_t now_realtime(void);
static void timer_thread_start(void);
static void *timer_main(void *arg);
static struct knote *timer_earliest(void);
static struct kqueue *kqueue_next(struct kqueue *kq);
static void timer_fire(struct knote *kn);
static int workloop_touch(struct knote *kn, const struct kevent_qos_s *change);
static bool workloop_state_matches(const struct kevent_qos_s *change);
static void workloop_sync_wait(struct knote *kn);
static void kqueue_request(struct kqueue *kq, bool manager);
static bool kqueue_deliverable(struct kqueue *kq, bool manager, uint32_t *qos);
static bool knote_deliverable(struct knote *kn, bool manager);
static bool knote_active(struct knote *kn);
static uint32_t thread_qos(int32_t priority);
static int kqueue_collect(struct kqueue *kq, bool manager,
		struct kevent_qos_s *events, int max_events, uint8_t **data,
		size_t *data_size);
static bool machport_receive(
		struct kevent_qos_s *event, uint8_t **data, size_t *data_size);
static void knote_delivered(struct knote *kn);

int
sys_kevent_qos(int fd, void *changelist, int nchanges, void *eventlist,
		int nevents, void *data_out, size_t *data_available,
		unsigned int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "kevent_qos(%d, %p, %d, %p, %d, %p, %p, %#x)\n", fd,
			changelist, nchanges, eventlist, nevents, data_out,
			(void *)data_available, flags);
#endif
	if (!(flags & KEVENT_FLAG_WORKQ)) {
		unimplemented();
	}

	pthread_mutex_lock(&lock);
	int result = kevent_internal(&workq_kqueue, changelist, nchanges,
			eventlist, nevents, data_out, data_available, flags);
	pthread_mutex_unlock(&lock);
	return result;
}

int
sys_kevent_id(uint64_t id, void *changelist, int nchanges, void *eventlist,
		int nevents, void *data_out, size_t *data_available,
		unsigned int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "kevent_id(%#lx, %p, %d, %p, %d, %p, %p, %#x)\n", id,
			changelist, nchanges, eventlist, nevents, data_out,
			(void *)data_available, flags);
#endif
	pthread_mutex_lock(&lock);
	int result;
	struct kqueue *kq = workloop_lookup(id, flags);
	if (kq == NULL) {
		result = (flags & KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST) ? _ENOENT
								     : _EEXIST;
	} else {
		result = kevent_internal(kq, changelist, nchanges, eventlist,
				nevents, data_out, data_available, flags);
	}
	pthread_mutex_unlock(&lock);
	return result;
}

static struct kqueue *
workloop_lookup(uint64_t id, unsigned int flags)
{
	for (struct kqueue *kq = workloops; kq != NULL; kq = kq->next) {
		if (kq->id == id) {
			return (flags & KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST)
					? NULL
					: kq;
		}
	}

	if (flags & KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST) {
		return NULL;
	}

	struct kqueue *kq = calloc(1, sizeof(*kq));
	kq->kind = KQUEUE_WORKLOOP;
	kq->id = id;
	kq->next = workloops;
	workloops = kq;
	return kq;
}

static int
kevent_internal(struct kqueue *kq, const struct kevent_qos_s *changes,
		int nchanges, struct kevent_qos_s *events, int nevents,
		uint8_t *data_out, size_t *data_available, unsigned int flags)
{
	int nerrors = 0;
	for (int i = 0; i < nchanges; i++) {
		int error = kevent_register(kq, &changes[i]);
		if ((error != 0 || (changes[i].flags & EV_RECEIPT))
				&& nerrors < nevents) {
			events[nerrors] = changes[i];
			events[nerrors].flags |= EV_ERROR;
			events[nerrors].data = -error;
			nerrors++;
		}
	}

	kqueue_request(kq, false);
	kqueue_request(kq, true);

	if (nerrors != 0 || (flags & KEVENT_FLAG_ERROR_EVENTS)
			|| nevents == 0) {
		return nerrors;
	}
	if (!(flags & KEVENT_FLAG_IMMEDIATE)) {
		unimplemented();
	}

	size_t data_size = (data_available != NULL) ? *data_available : 0;
	int count = kqueue_collect(kq, flags & KEVENT_FLAG_WORKQ_MANAGER,
			events, nevents, &data_out, &data_size);
	if (data_available != NULL) {
		*data_available = data_size;
	}
	return count;
}

static int
kevent_register(struct kqueue *kq, const struct kevent_qos_s *change)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"  kevent(ident=%#lx, filter=%d, flags=%#x, qos=%#x, "
			"udata=%#lx, fflags=%#x, data=%#lx, ext=[%#lx, %#lx, "
			"%#lx, %#lx])\n",
			change->ident, change->filter, change->flags,
			change->qos, change->udata, change->fflags,
			change->data, change->ext[0], change->ext[1],
			change->ext[2], change->ext[3]);
#endif
	struct knote *kn = knote_find(kq, change);

	if (change->filter == EVFILT_WORKLOOP) {
		if (change->fflags & NOTE_WL_END_OWNERSHIP) {
			kq->owned = false;
		}
		if (!workloop_state_matches(change)) {
			return (change->fflags & NOTE_WL_IGNORE_ESTALE)
					? 0
					: _ESTALE;
		}
	}

	if (change->flags & EV_DELETE) {
		if (kn == NULL) {
			return _ENOENT;
		}
		knote_detach(kn);
		return 0;
	}

	int error = 0;
	if (kn == NULL) {
		if (!(change->flags & EV_ADD)) {
			return _ENOENT;
		}
		kn = knote_attach(kq, change);
	} else {
		error = knote_touch(kn, change);
	}

	if (change->flags & EV_DISABLE) {
		kn->disabled = true;
	}
	if (change->flags & EV_ENABLE) {
		kn->disabled = false;
	}

	if (error == 0 && change->filter == EVFILT_WORKLOOP
			&& (change->fflags & NOTE_WL_COMMANDS_MASK)
					== NOTE_WL_SYNC_WAIT) {
		workloop_sync_wait(kn);
	}
	return error;
}

static struct knote *
knote_find(struct kqueue *kq, const struct kevent_qos_s *change)
{
	for (struct knote *kn = kq->knotes; kn != NULL; kn = kn->next) {
		if (kn->kev.ident != change->ident
				|| kn->kev.filter != change->filter) {
			continue;
		}
		if ((change->flags & EV_UDATA_SPECIFIC)
				&& kn->kev.udata != change->udata) {
			continue;
		}
		return kn;
	}
	return NULL;
}

static struct knote *
knote_attach(struct kqueue *kq, const struct kevent_qos_s *change)
{
	struct knote *kn = calloc(1, sizeof(*kn));
	kn->kq = kq;
	kn->kev = *change;
	kn->kev.flags &= ~(EV_ADD | EV_ENABLE | EV_DISABLE | EV_RECEIPT
			| EV_VANISHED);
	kn->kev.fflags = 0;
	kn->kev.data = 0;
	kn->manager = kq->kind == KQUEUE_WORKQ
			&& (change->qos & PTHREAD_PRIORITY_EVENT_MANAGER_FLAG);
	kn->next = kq->knotes;
	kq->knotes = kn;

	knote_touch(kn, change);
	return kn;
}

static void
knote_detach(struct knote *kn)
{
	struct kqueue *kq = kn->kq;
	for (struct knote **p = &kq->knotes; *p != NULL; p = &(*p)->next) {
		if (*p == kn) {
			*p = kn->next;
			break;
		}
	}
	free(kn);
}

static int
knote_touch(struct knote *kn, const struct kevent_qos_s *change)
{
	if (!(change->flags & EV_UDATA_SPECIFIC)) {
		kn->kev.udata = change->udata;
	}
	kn->kev.qos = change->qos;

	switch (change->filter) {
	case EVFILT_USER:
		user_touch(kn, change);
		return 0;
	case EVFILT_TIMER:
		kn->kev.fflags = change->fflags;
		kn->kev.data = change->data;
		kn->kev.ext[1] = change->ext[1];
		timer_arm(kn);
		return 0;
	case EVFILT_WORKLOOP:
		return workloop_touch(kn, change);
	default:
		kn->kev.fflags = change->fflags;
		memcpy(kn->kev.ext, change->ext, sizeof(kn->kev.ext));
		return 0;
	}
}

static void
user_touch(struct knote *kn, const struct kevent_qos_s *change)
{
	uint32_t fflags = change->fflags & NOTE_FFLAGSMASK;
	switch (change->fflags & NOTE_FFCTRLMASK) {
	case NOTE_FFAND:
		kn->kev.fflags &= fflags;
		break;
	case NOTE_FFOR:
		kn->kev.fflags |= fflags;
		break;
	case NOTE_FFCOPY:
		kn->kev.fflags = fflags;
		break;
	}

	if (change->fflags & NOTE_TRIGGER) {
		kn->active = true;
	}
}

static void
timer_arm(struct knote *kn)
{
	uint32_t fflags = kn->kev.fflags;
	uint64_t nanoseconds = timer_nanoseconds(fflags, kn->kev.data);

	if (fflags & NOTE_ABSOLUTE) {
		kn->interval = 0;
		kn->deadline = (fflags & NOTE_MACHTIME) ? nanoseconds
							: now_monotonic()
						+ (nanoseconds > now_realtime() ? nanoseconds - now_realtime()
										: 0);
	} else {
		kn->interval = (kn->kev.flags & (EV_ONESHOT | EV_DISPATCH))
				? 0
				: nanoseconds;
		kn->deadline = now_monotonic() + nanoseconds;
	}
	kn->kev.data = 0;
	kn->active = false;

	timer_thread_start();
	pthread_cond_signal(&timer_wakeup);
}

static uint64_t
timer_nanoseconds(uint32_t fflags, int64_t data)
{
	if (fflags & NOTE_SECONDS) {
		return data * 1000000000ULL;
	}
	if (fflags & NOTE_USECONDS) {
		return data * 1000ULL;
	}
	if (fflags & (NOTE_NSECONDS | NOTE_MACHTIME)) {
		return data;
	}
	return data * 1000000ULL;
}

static uint64_t
now_monotonic(void)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static uint64_t
now_realtime(void)
{
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	return now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static void
timer_thread_start(void)
{
	if (timer_thread_started) {
		return;
	}
	timer_thread_started = true;

	pthread_condattr_t attr;
	pthread_condattr_init(&attr);
	pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	pthread_cond_init(&timer_wakeup, &attr);
	pthread_condattr_destroy(&attr);

	sigset_t all, previous;
	sigfillset(&all);
	pthread_sigmask(SIG_SETMASK, &all, &previous);
	pthread_t handle;
	pthread_create(&handle, NULL, timer_main, NULL);
	pthread_detach(handle);
	pthread_sigmask(SIG_SETMASK, &previous, NULL);
}

static void *
timer_main(void *arg)
{
	pthread_mutex_lock(&lock);
	while (true) {
		struct knote *kn = timer_earliest();
		if (kn == NULL) {
			pthread_cond_wait(&timer_wakeup, &lock);
		} else if (now_monotonic() >= kn->deadline) {
			timer_fire(kn);
		} else {
			struct timespec deadline = {
					.tv_sec = kn->deadline / 1000000000ULL,
					.tv_nsec = kn->deadline % 1000000000ULL,
			};
			pthread_cond_timedwait(&timer_wakeup, &lock, &deadline);
		}
	}
	return NULL;
}

static struct knote *
timer_earliest(void)
{
	struct knote *earliest = NULL;
	struct kqueue *kq = &workq_kqueue;
	while (kq != NULL) {
		for (struct knote *kn = kq->knotes; kn != NULL; kn = kn->next) {
			if (kn->kev.filter == EVFILT_TIMER && kn->deadline != 0
					&& (earliest == NULL
							|| kn->deadline < earliest->deadline)) {
				earliest = kn;
			}
		}
		kq = kqueue_next(kq);
	}
	return earliest;
}

static struct kqueue *
kqueue_next(struct kqueue *kq)
{
	return (kq == &workq_kqueue) ? workloops : kq->next;
}

static void
timer_fire(struct knote *kn)
{
	kn->kev.data++;
	kn->active = true;
	if (kn->interval != 0) {
		kn->deadline += kn->interval;
	} else {
		kn->deadline = 0;
	}
	kqueue_request(kn->kq, kn->manager);
}

static int
workloop_touch(struct knote *kn, const struct kevent_qos_s *change)
{
	kn->kev.fflags = change->fflags;
	memcpy(kn->kev.ext, change->ext, sizeof(kn->kev.ext));

	switch (change->fflags & NOTE_WL_COMMANDS_MASK) {
	case NOTE_WL_THREAD_REQUEST:
		kn->active = true;
		return 0;
	case NOTE_WL_SYNC_WAIT:
		return 0;
	case NOTE_WL_SYNC_WAKE:
		kn->kq->owned = true;
		kn->woken = true;
		pthread_cond_broadcast(&sync_wakeup);
		return 0;
	default:
		unimplemented();
	}
}

static bool
workloop_state_matches(const struct kevent_qos_s *change)
{
	uint64_t mask = change->ext[EV_EXTIDX_WL_MASK];
	if (mask == 0) {
		return true;
	}

	uint64_t current = __atomic_load_n(
			(uint64_t *)change->ext[EV_EXTIDX_WL_ADDR],
			__ATOMIC_ACQUIRE);
	return (current & mask) == (change->ext[EV_EXTIDX_WL_VALUE] & mask);
}

static void
workloop_sync_wait(struct knote *kn)
{
	kqueue_request(kn->kq, false);
	while (!kn->woken) {
		pthread_cond_wait(&sync_wakeup, &lock);
	}
}

static void
kqueue_request(struct kqueue *kq, bool manager)
{
	uint32_t qos;
	if (kq->bound[manager] || kq->requested[manager] || kq->owned
			|| !kqueue_deliverable(kq, manager, &qos)) {
		return;
	}

	kq->requested[manager] = true;
	workq_request_kqueue(kq, qos, manager);
}

static bool
kqueue_deliverable(struct kqueue *kq, bool manager, uint32_t *qos)
{
	bool deliverable = false;
	*qos = 0;
	for (struct knote *kn = kq->knotes; kn != NULL; kn = kn->next) {
		if (knote_deliverable(kn, manager)) {
			deliverable = true;
			uint32_t kn_qos = thread_qos(kn->kev.qos);
			if (kn_qos > *qos) {
				*qos = kn_qos;
			}
		}
	}
	if (*qos == 0) {
		*qos = THREAD_QOS_LEGACY;
	}
	return deliverable;
}

static bool
knote_deliverable(struct knote *kn, bool manager)
{
	return !kn->disabled && kn->manager == manager && knote_active(kn);
}

static bool
knote_active(struct knote *kn)
{
	switch (kn->kev.filter) {
	case EVFILT_MACHPORT:
		return ipc_port_peek(kn->kev.ident);
	default:
		return kn->active;
	}
}

static uint32_t
thread_qos(int32_t priority)
{
	return ffs(((uint32_t)priority & PTHREAD_PRIORITY_QOS_CLASS_MASK)
			>> PTHREAD_PRIORITY_QOS_CLASS_SHIFT);
}

static int
kqueue_collect(struct kqueue *kq, bool manager, struct kevent_qos_s *events,
		int max_events, uint8_t **data, size_t *data_size)
{
	int count = 0;
	struct knote *kn = kq->knotes;
	while (kn != NULL && count < max_events) {
		struct knote *next = kn->next;
		if (knote_deliverable(kn, manager)) {
			events[count] = kn->kev;
			if (kn->kev.filter != EVFILT_MACHPORT
					|| machport_receive(&events[count],
							data, data_size)) {
#ifdef ENABLE_STRACE
				fprintf(stderr,
						"  deliver(kq=%#lx, "
						"ident=%#lx, "
						"filter=%d, fflags=%#x)\n",
						kq->id, kn->kev.ident,
						kn->kev.filter,
						events[count].fflags);
#endif
				count++;
				knote_delivered(kn);
			}
		}
		kn = next;
	}
	return count;
}

int
kevent_bind(struct kqueue *kq, bool manager, struct kevent_qos_s *events,
		int max_events, uint8_t *data, size_t data_size)
{
	pthread_mutex_lock(&lock);
#ifdef ENABLE_STRACE
	fprintf(stderr, "  bind(kq=%#lx, manager=%d, tid=%d)\n", kq->id,
			manager, gettid());
#endif
	kq->requested[manager] = false;
	kq->bound[manager] = true;
	int count = kqueue_collect(
			kq, manager, events, max_events, &data, &data_size);
	pthread_mutex_unlock(&lock);
	return count;
}

static bool
machport_receive(struct kevent_qos_s *event, uint8_t **data, size_t *data_size)
{
	uint32_t options = event->fflags;
	if (!(options & MACH_RCV_MSG)) {
		unimplemented();
	}

	bool use_data = event->ext[1] == 0;
	mach_msg_header_t *msg = use_data ? (mach_msg_header_t *)*data
					  : (mach_msg_header_t *)event->ext[0];
	mach_msg_size_t size = use_data ? *data_size : event->ext[1];
	mach_msg_return_t mr = ipc_mach_msg(msg,
			MACH64_RCV_MSG | MACH_RCV_TIMEOUT
					| (options & (MACH_RCV_LARGE | MACH_RCV_TRAILER_MASK)),
			0, size, event->ident, 0);
	if (mr == MACH_RCV_TIMED_OUT) {
		return false;
	}

	size = msg->msgh_size;
	if (mr == MACH_MSG_SUCCESS) {
		size += ((mach_msg_trailer_t *)((uint8_t *)msg + size))
					->msgh_trailer_size;
		if (use_data) {
			size_t used = (size + 7) & ~7;
			*data += used;
			*data_size -= used;
		}
	}

	event->fflags = mr;
	event->data = event->ident;
	event->ext[0] = (uint64_t)msg;
	event->ext[1] = size;
	event->ext[2] = 0;
	return true;
}

static void
knote_delivered(struct knote *kn)
{
	if (kn->kev.flags & EV_ONESHOT) {
		knote_detach(kn);
		return;
	}

	if (kn->kev.flags & EV_DISPATCH) {
		kn->disabled = true;
	}

	if (kn->kev.flags & (EV_CLEAR | EV_DISPATCH)) {
		kn->active = false;
		if (kn->kev.filter == EVFILT_TIMER) {
			kn->kev.data = 0;
		}
	}
}

void
kevent_unbind(struct kqueue *kq, bool manager,
		const struct kevent_qos_s *changes, int nchanges)
{
	pthread_mutex_lock(&lock);
#ifdef ENABLE_STRACE
	fprintf(stderr, "  unbind(kq=%#lx, manager=%d, tid=%d)\n", kq->id,
			manager, gettid());
#endif
	for (int i = 0; i < nchanges; i++) {
		kevent_register(kq, &changes[i]);
	}
	kq->bound[manager] = false;
	kqueue_request(kq, false);
	kqueue_request(kq, true);
	pthread_mutex_unlock(&lock);
}

uint64_t
kevent_kqid(struct kqueue *kq)
{
	return kq->id;
}

void
kevent_machport_arrival(mach_port_name_t name)
{
	pthread_mutex_lock(&lock);
	struct kqueue *kq = &workq_kqueue;
	while (kq != NULL) {
		for (struct knote *kn = kq->knotes; kn != NULL; kn = kn->next) {
			if (kn->kev.filter == EVFILT_MACHPORT
					&& kn->kev.ident == name) {
				kqueue_request(kq, kn->manager);
			}
		}
		kq = kqueue_next(kq);
	}
	pthread_mutex_unlock(&lock);
}

int
sys_kqueue_workloop_ctl(
		user_addr_t cmd, uint64_t options, user_addr_t addr, size_t sz)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "kqueue_workloop_ctl(%p, %p, %p, %p)\n", (void *)cmd,
			(void *)options, (void *)addr, (void *)sz);
#endif
	unimplemented();
}
