# NetworkManager Makefile helpers

set_sanitizer_env = \
	[ -n "$(SANITIZER_ENV)" ] && export $(SANITIZER_ENV) ; \
	if [ -n "$(1)" ] && echo $(CFLAGS) | grep -e -fsanitize=address ; then \
		export LD_PRELOAD="$${LD_PRELOAD}:$$(ldd $(1) | grep libasan\.so\.. -o | head -n 1)"; \
	fi

check_so_symbols = \
	$(call set_sanitizer_env,$(1)); \
	LD_BIND_NOW=1 LD_PRELOAD=$${LD_PRELOAD}:$(1) $(top_builddir)/src/NetworkManager --version >/dev/null
