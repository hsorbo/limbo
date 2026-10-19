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

#include <CoreFoundation/CoreFoundation.h>

#include "check.h"

static void tick(CFRunLoopTimerRef timer, void *info);

int
main(void)
{
	int ticks = 0;
	CFRunLoopTimerContext context = {.info = &ticks};
	CFRunLoopTimerRef timer = CFRunLoopTimerCreate(NULL,
			CFAbsoluteTimeGetCurrent() + 0.01, 0.01, 0, 0, tick,
			&context);
	CFRunLoopAddTimer(CFRunLoopGetCurrent(), timer, kCFRunLoopDefaultMode);
	CHECK(CFRunLoopRunInMode(kCFRunLoopDefaultMode, 5, false)
			== kCFRunLoopRunStopped);
	CHECK(ticks == 3);
	CFRelease(timer);

	CFURLRef url = CFURLCreateWithFileSystemPath(
			NULL, CFSTR("/usr/lib"), kCFURLPOSIXPathStyle, true);
	CFBooleanRef directory = NULL;
	CHECK(CFURLCopyResourcePropertyForKey(
			url, kCFURLIsDirectoryKey, &directory, NULL));
	CHECK(directory == kCFBooleanTrue);
	CFRelease(directory);
	CFRelease(url);

	CFStringRef string = CFStringCreateWithFormat(
			NULL, NULL, CFSTR("%d-%s"), 42, "limbo");
	CHECK(CFStringCompare(string, CFSTR("42-limbo"), 0)
			== kCFCompareEqualTo);
	CFRelease(string);
	return 0;
}

static void
tick(CFRunLoopTimerRef timer, void *info)
{
	int *ticks = info;
	if (++*ticks == 3) {
		CFRunLoopStop(CFRunLoopGetCurrent());
	}
}
