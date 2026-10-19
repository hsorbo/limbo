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

#include <dispatch/dispatch.h>
#include <stdatomic.h>

#include "check.h"

int
main(void)
{
	dispatch_queue_t concurrent
			= dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0);
	dispatch_group_t group = dispatch_group_create();
	__block atomic_int counter = 0;
	for (int i = 0; i < 100; i++) {
		dispatch_group_async(group, concurrent, ^{
		  atomic_fetch_add(&counter, 1);
		});
	}
	CHECK(dispatch_group_wait(group, DISPATCH_TIME_FOREVER) == 0);
	CHECK(counter == 100);

	dispatch_apply(64, concurrent, ^(size_t i) {
	  atomic_fetch_add(&counter, (int)i);
	});
	CHECK(counter == 100 + 64 * 63 / 2);

	dispatch_queue_t serial = dispatch_queue_create("limbo.serial", NULL);
	__block int order = 0;
	for (int i = 0; i < 10; i++) {
		dispatch_async(serial, ^{
		  CHECK(order == i);
		  order++;
		});
	}
	dispatch_sync(serial, ^{
	  CHECK(order == 10);
	});

	dispatch_semaphore_t done = dispatch_semaphore_create(0);
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_MSEC),
			serial, ^{
			  dispatch_semaphore_signal(done);
			});
	CHECK(dispatch_semaphore_wait(done,
			      dispatch_time(DISPATCH_TIME_NOW,
					      5 * NSEC_PER_SEC))
			== 0);

	dispatch_source_t timer = dispatch_source_create(
			DISPATCH_SOURCE_TYPE_TIMER, 0, 0, serial);
	__block int ticks = 0;
	dispatch_source_set_timer(
			timer, DISPATCH_TIME_NOW, 5 * NSEC_PER_MSEC, 0);
	dispatch_source_set_event_handler(timer, ^{
	  if (++ticks == 3) {
		  dispatch_source_cancel(timer);
		  dispatch_semaphore_signal(done);
	  }
	});
	dispatch_resume(timer);
	CHECK(dispatch_semaphore_wait(done,
			      dispatch_time(DISPATCH_TIME_NOW,
					      5 * NSEC_PER_SEC))
			== 0);
	CHECK(ticks == 3);
	return 0;
}
