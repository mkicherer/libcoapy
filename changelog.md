2024.12.17
----------

* use generated llapi.py file by genbindgen
* fragile event loop integration for Windows system replaced with new libcoap
  function `coap_io_get_fds()`, requires libcoap > v4.3.5 on Windows
