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

#include <errno.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#include "ipc.h"
#include "semaphore.h"

struct semaphore {
	pthread_mutex_t lock;
	pthread_cond_t wakeup;
	int value;
	int wakeups;
};

static kern_return_t wait_until(
		struct semaphore *semaphore, const struct timespec *deadline);
static struct timespec deadline_after(mach_timespec_t timeout);

kern_return_t
semaphore_alloc(int value, semaphore_t *name)
{
	struct semaphore *semaphore = calloc(1, sizeof(*semaphore));
	pthread_mutex_init(&semaphore->lock, NULL);
	pthread_cond_init(&semaphore->wakeup, NULL);
	semaphore->value = value;
	*name = ipc_kobject_alloc(IPC_KOBJECT_SEMAPHORE, semaphore);
	return KERN_SUCCESS;
}

kern_return_t
semaphore_dealloc(semaphore_t name)
{
	struct semaphore *semaphore
			= ipc_kobject_lookup(name, IPC_KOBJECT_SEMAPHORE);
	if (semaphore == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	ipc_kobject_destroy(name);
	pthread_cond_destroy(&semaphore->wakeup);
	pthread_mutex_destroy(&semaphore->lock);
	free(semaphore);
	return KERN_SUCCESS;
}

kern_return_t
semaphore_signal(semaphore_t name)
{
	struct semaphore *semaphore
			= ipc_kobject_lookup(name, IPC_KOBJECT_SEMAPHORE);
	if (semaphore == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	pthread_mutex_lock(&semaphore->lock);
	if (++semaphore->value <= 0) {
		semaphore->wakeups++;
		pthread_cond_signal(&semaphore->wakeup);
	}
	pthread_mutex_unlock(&semaphore->lock);
	return KERN_SUCCESS;
}

kern_return_t
semaphore_signal_all(semaphore_t name)
{
	struct semaphore *semaphore
			= ipc_kobject_lookup(name, IPC_KOBJECT_SEMAPHORE);
	if (semaphore == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	pthread_mutex_lock(&semaphore->lock);
	if (semaphore->value < 0) {
		semaphore->wakeups -= semaphore->value;
		semaphore->value = 0;
		pthread_cond_broadcast(&semaphore->wakeup);
	}
	pthread_mutex_unlock(&semaphore->lock);
	return KERN_SUCCESS;
}

kern_return_t
semaphore_wait(semaphore_t name)
{
	struct semaphore *semaphore
			= ipc_kobject_lookup(name, IPC_KOBJECT_SEMAPHORE);
	if (semaphore == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	return wait_until(semaphore, NULL);
}

static kern_return_t
wait_until(struct semaphore *semaphore, const struct timespec *deadline)
{
	kern_return_t kr = KERN_SUCCESS;
	pthread_mutex_lock(&semaphore->lock);
	if (--semaphore->value < 0) {
		while (semaphore->wakeups == 0) {
			int error = (deadline != NULL)
					? pthread_cond_timedwait(
							  &semaphore->wakeup,
							  &semaphore->lock,
							  deadline)
					: pthread_cond_wait(&semaphore->wakeup,
							  &semaphore->lock);
			if (error == ETIMEDOUT && semaphore->wakeups == 0) {
				semaphore->value++;
				kr = KERN_OPERATION_TIMED_OUT;
				goto out;
			}
		}
		semaphore->wakeups--;
	}
out:
	pthread_mutex_unlock(&semaphore->lock);
	return kr;
}

kern_return_t
semaphore_timedwait(semaphore_t name, mach_timespec_t timeout)
{
	struct semaphore *semaphore
			= ipc_kobject_lookup(name, IPC_KOBJECT_SEMAPHORE);
	if (semaphore == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	struct timespec deadline = deadline_after(timeout);
	return wait_until(semaphore, &deadline);
}

static struct timespec
deadline_after(mach_timespec_t timeout)
{
	struct timespec deadline;
	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += timeout.tv_sec;
	deadline.tv_nsec += timeout.tv_nsec;
	if (deadline.tv_nsec >= 1000000000) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000;
	}
	return deadline;
}

kern_return_t
semaphore_wait_signal(semaphore_t wait_name, semaphore_t signal_name)
{
	kern_return_t kr = semaphore_signal(signal_name);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	return semaphore_wait(wait_name);
}

kern_return_t
semaphore_timedwait_signal(semaphore_t wait_name, semaphore_t signal_name,
		mach_timespec_t timeout)
{
	kern_return_t kr = semaphore_signal(signal_name);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	return semaphore_timedwait(wait_name, timeout);
}
