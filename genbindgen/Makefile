
-include Makefile.local

PYTHON?=python3

GENBINDGEN_DIR?=
CLIB_HEADER=$(INCLUDE_DIR)/coap3/coap.h

coap.py: $(GENBINDGEN_DIR)genbindgen.py Makefile libcoap.cfg.py
	[ ! -e $@ ] || cp $@ $@.bkp
	PYTHONPATH=$(GENBINDGEN_DIR) $(PYTHON) $(GENBINDGEN_DIR)genbindgen.py \
		-l python \
		--config libcoap.cfg.py \
		--clang-args="-I$(INCLUDE_DIR)" \
		$(CLIB_HEADER)
	diff -u $@.bkp $@ || :
