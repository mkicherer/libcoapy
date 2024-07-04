libcoapy
========

libcoapy project enables communication over the CoAP protocol (RFC 7252). The
`llapi` module provides ctypes-based wrappers for the [libcoap](https://libcoap.net/)
C library. The `libcoapy` module uses `llapi` to provide a high-level class interface
to the libcoap functions.

Dependencies:
-------------

 - [libcoap](https://libcoap.net/)

Status
------

This project is still in early development. Several functions of the libcoap
library are not yet available and existing high-level libcoapy APIs might change
in the future.

Example: client
---------------

```python
from libcoapy import *

if len(sys.argv) < 2:
	uri_str = "coap://localhost"
else:
	uri_str = sys.argv[1]

ctx = CoapContext()

session = ctx.newSession(uri_str)

def rx_cb(session, tx_msg, rx_msg, mid):
	print(rx_msg.payload)
	session.ctx.stop_loop()

session.sendMessage(path=".well-known/core", response_callback=rx_cb)

ctx.loop()
```

Example: server
---------------

```python
from libcoapy import *

def echo_handler(resource, session, request, query, response):
	response.payload = request.payload

def time_handler(resource, session, request, query, response):
	import datetime
	now = datetime.datetime.now()
	response.payload = str(now)

ctx = CoapContext()
ctx.addEndpoint("coap://[::]")

time_rs = CoapResource(ctx, "time")
time_rs.addHandler(time_handler)
ctx.addResource(time_rs)

echo_rs = CoapResource(ctx, "echo")
echo_rs.addHandler(echo_handler)
ctx.addResource(echo_rs)

ctx.loop()
```

More examples can be found in the `examples` directory.
