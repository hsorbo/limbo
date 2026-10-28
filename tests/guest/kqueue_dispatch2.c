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

#include <errno.h>
#include <sys/event.h>
#include <unistd.h>

#include "check.h"

#define DISPATCH2 (EV_DISPATCH | EV_UDATA_SPECIFIC)

static int kq;

static int
change(uintptr_t ident, uint16_t flags, uint32_t fflags, void *udata)
{
	struct kevent ch;
	EV_SET(&ch, ident, EVFILT_USER, flags, fflags, 0, udata);
	return kevent(kq, &ch, 1, NULL, 0, NULL);
}

static int
collect(struct kevent *events, int count)
{
	struct timespec zero = {0, 0};
	return kevent(kq, NULL, 0, events, count, &zero);
}

int
main(void)
{
	kq = kqueue();
	CHECK(kq != -1);
	void *udata = (void *)0x1234;
	struct kevent events[4];

	CHECK(change(7, EV_ADD | EV_ENABLE | DISPATCH2, 0, udata) == 0);
	CHECK(change(7, EV_DELETE | DISPATCH2, 0, udata) == 0);

	CHECK(change(7, EV_ADD | EV_ENABLE | DISPATCH2, 0, udata) == 0);
	CHECK(change(7, DISPATCH2, NOTE_TRIGGER, udata) == 0);
	CHECK(collect(events, 4) == 1);
	CHECK(events[0].ident == 7 && (events[0].flags & DISPATCH2) == DISPATCH2);
	CHECK(change(7, EV_DELETE | DISPATCH2, 0, udata) == -1
			&& errno == EINPROGRESS);
	CHECK(collect(events, 4) == 0);
	CHECK(change(7, EV_DELETE | EV_ENABLE | DISPATCH2, 0, udata) == 0);
	CHECK(change(7, EV_DELETE | EV_ENABLE | DISPATCH2, 0, udata) == -1
			&& errno == ENOENT);

	CHECK(change(7, EV_ADD | EV_ENABLE | DISPATCH2, 0, udata) == 0);
	CHECK(change(7, DISPATCH2, NOTE_TRIGGER, udata) == 0);
	CHECK(collect(events, 4) == 1);
	CHECK(change(7, EV_ENABLE | DISPATCH2, 0, udata) == 0);
	CHECK(change(7, EV_DELETE | DISPATCH2, 0, udata) == 0);

	udata = (void *)0x5678;
	CHECK(change(8, EV_ADD | EV_ENABLE | EV_ONESHOT | DISPATCH2, 0, udata)
			== 0);
	CHECK(change(8, EV_ONESHOT | DISPATCH2, NOTE_TRIGGER, udata) == 0);
	CHECK(collect(events, 4) == 1);
	CHECK(events[0].ident == 8 && (events[0].flags & EV_ONESHOT));
	CHECK(change(8, EV_DELETE | EV_ONESHOT | DISPATCH2, 0, udata) == -1
			&& errno == EINPROGRESS);
	CHECK(change(8, EV_DELETE | EV_ENABLE | EV_ONESHOT | DISPATCH2, 0,
			      udata)
			== 0);

	close(kq);
	return 0;
}
