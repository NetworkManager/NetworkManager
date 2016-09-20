# NetworkManager Makefile helpers

check_so_symbols = \
	LD_BIND_NOW=1 LD_PRELOAD=$(1) $(top_builddir)/src/NetworkManager --version >/dev/null
