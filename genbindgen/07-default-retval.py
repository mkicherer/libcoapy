
for fct in library_functions:
	if (
		"restype" in fct
		and fct["restype"] == ct.c_int
		and "res_error" not in fct
		and "expect" not in fct
		and fct.get("llapi_check", True) is True
		):
		fct["res_error"] = 0
