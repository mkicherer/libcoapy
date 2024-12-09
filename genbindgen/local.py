COAP_IO_NO_WAIT = ct.c_uint32(-1).value

libcoap_initialized = False

def genbindgen_pre_ct_call_hook(fdict, nargs, kwargs):
	global libcoap_initialized
	
	if not libcoap_initialized:
		libcoap_initialized = True
		coap_startup()

def bytes2uint8p(b, cast=ct.POINTER(ct.c_ubyte)):
	if b is None:
		return None
	return ct.cast(ct.create_string_buffer(b), cast)
