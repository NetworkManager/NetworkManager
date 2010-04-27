noinst_LTLIBRARIES = libnm-logging.la

libnm_logging_la_SOURCES = \
	nm-logging.c \
	nm-logging.h

libnm_logging_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	-DLIBEXECDIR=\"$(libexecdir)\" \
	-DG_DISABLE_DEPRECATED

libnm_logging_la_LIBADD = \
	-ldl \
	$(GLIB_LIBS)

