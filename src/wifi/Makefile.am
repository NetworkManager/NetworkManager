INCLUDES = \
	-I${top_srcdir}/include \
	-I${top_builddir}/include \
	-I${top_srcdir}/src/logging \
	-I${top_srcdir}/libnm-util \
	-I${top_builddir}/libnm-util \
	-I${top_srcdir}/src

noinst_LTLIBRARIES = libwifi-utils.la

libwifi_utils_la_SOURCES = \
	wifi-utils.c \
	wifi-utils.h \
	wifi-utils-private.h \
	wifi-utils-nl80211.c \
	wifi-utils-nl80211.h

if WITH_WEXT
libwifi_utils_la_SOURCES += wifi-utils-wext.c wifi-utils-wext.h
endif

libwifi_utils_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(LIBNL_CFLAGS)

libwifi_utils_la_LIBADD = \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS) \
	$(LIBNL_LIBS)

