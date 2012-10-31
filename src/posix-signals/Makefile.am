noinst_LTLIBRARIES = libnm-posix-signals.la

libnm_posix_signals_la_SOURCES = \
	nm-posix-signals.c \
	nm-posix-signals.h

libnm_posix_signals_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	-DLIBEXECDIR=\"$(libexecdir)\"

libnm_posix_signals_la_LIBADD = \
	-ldl \
	$(GLIB_LIBS)

