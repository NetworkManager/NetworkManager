SUBDIRS = . tests

noinst_LTLIBRARIES = libnm-config.la

libnm_config_la_SOURCES = \
	nm-config.c \
	nm-config.h

libnm_config_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/src/logging \
	-DNMCONFDIR=\"$(nmconfdir)\"

libnm_config_la_LIBADD = \
	$(GLIB_LIBS)

