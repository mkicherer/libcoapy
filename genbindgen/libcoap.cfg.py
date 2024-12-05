{
	"clang_args": ["-DCOAP_API=", "-DCOAP_DEPRECATED=", "-DCOAP_STATIC_INLINE=",],
	"opaque_types": ["coap_pdu_t"],
	"functions": {
		"coap_split_uri": {
			3: ["in", "out"],
			},
		"coap_resolve_address_info": {
			1: ["in"],
			2: ["in"],
			3: ["in"],
			4: ["in"],
			5: ["in"],
			6: ["in"],
			7: ["in"],
			8: ["in"],
			},
		"coap_new_context": {
			1: ["in"],
			},
		"coap_print_addr": {
			"address": ["in"],
			},
		"coap_split_uri": {
			"uri": ["in","out"],
			},
		"coap_uri_into_optlist": {
			"uri": ["in"],
			"optlist_chain": ["out"],
			},
		"coap_get_data_large": {
			"len": ["in", "out"],
			"data": ["out"],
			"offset": ["in", "out"],
			"total": ["in", "out"],
			},
		}
}
