SUBDIRS = . tests

noinst_LTLIBRARIES = libnm-config.la

libnm_config_la_SOURCES = \
	nm-config.c \
	nm-config.h \
	nm-config-device.c \
	nm-config-device.h

libnm_config_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	-I$(top_srcdir)/src/logging \
	-DNMCONFDIR=\"$(nmconfdir)\" \
	-DNMSTATEDIR=\"$(nmstatedir)\"

libnm_config_la_LIBADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS)

