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
#include <string.h>
#include <xpc/xpc.h>

#include "check.h"

int
main(void)
{
	dispatch_queue_t queue = dispatch_queue_create("limbo.xpc", NULL);
	xpc_connection_t listener = xpc_connection_create(NULL, queue);
	xpc_connection_set_event_handler(listener, ^(xpc_object_t peer) {
	  if (xpc_get_type(peer) != XPC_TYPE_CONNECTION) {
		  return;
	  }
	  xpc_connection_set_event_handler(peer, ^(xpc_object_t message) {
	    if (xpc_get_type(message) != XPC_TYPE_DICTIONARY) {
		    return;
	    }
	    int64_t value = xpc_dictionary_get_int64(message, "value");
	    xpc_object_t reply = xpc_dictionary_create_reply(message);
	    xpc_dictionary_set_int64(reply, "value", value * 2);
	    xpc_dictionary_set_string(reply, "greeting", "hello");
	    xpc_connection_send_message(peer, reply);
	  });
	  xpc_connection_resume(peer);
	});
	xpc_connection_resume(listener);

	xpc_endpoint_t endpoint = xpc_endpoint_create(listener);
	xpc_connection_t client = xpc_connection_create_from_endpoint(endpoint);
	xpc_connection_set_event_handler(client,
			^(xpc_object_t event){
			});
	xpc_connection_resume(client);

	for (int64_t i = 1; i <= 3; i++) {
		xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
		xpc_dictionary_set_int64(message, "value", i);
		xpc_object_t reply
				= xpc_connection_send_message_with_reply_sync(
						client, message);
		CHECK(xpc_get_type(reply) == XPC_TYPE_DICTIONARY);
		CHECK(xpc_dictionary_get_int64(reply, "value") == i * 2);
		CHECK(strcmp(xpc_dictionary_get_string(reply, "greeting"),
				      "hello")
				== 0);
	}

	xpc_connection_cancel(client);
	xpc_connection_cancel(listener);
	return 0;
}
