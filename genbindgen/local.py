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

def c_uint8_p_to_str(uint8p, length):
	b = ct.string_at(uint8p, length)
	try:
		return b.decode()
	except:
		return b

class coap_string_t(LStructure):
	_fields_ = [("length", ct.c_size_t), ("s", ct.POINTER(ct.c_uint8))]
	
	def __init__(self, value=None):
		super().__init__()
		
		if value:
			if isinstance(value, str):
				b = value.encode()
			else:
				b = value
			
			self.s = bytes2uint8p(b)
			self.length = ct.c_size_t(len(b))
	
	def __str__(self):
		return str(c_uint8_p_to_str(self.s, self.length))

class coap_str_const_t(coap_string_t):
	pass

class coap_binary_t(coap_string_t):
	def __str__(self):
		return str([ "0x%02x" % (self.s[i]) for i in range(self.length)])

class coap_bin_const_t(coap_binary_t):
	pass
