INCLUDES = -I${top_srcdir} -I${top_srcdir}/include

lib_LTLIBRARIES=libnm-util.la

libnm_util_la_CPPFLAGS =				\
	$(GLIB_CFLAGS)					\
	$(DBUS_CFLAGS)					\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DG_DISABLE_DEPRECATED			\
	-DGDK_DISABLE_DEPRECATED			\
	-DGNOME_DISABLE_DEPRECATED		\
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"

libnm_util_la_SOURCES=			\
	dbus-dict-helpers.c			\
	dbus-dict-helpers.h		\
	nm-connection.c			\
	nm-connection.h			\
	nm-setting.c			\
	nm-setting.h			\
	nm-utils.c			\
	nm-utils.h

libnm_util_la_LDFLAGS= $(GLIB_LIBS) $(DBUS_LIBS)

libnm_util_la_CFLAGS=-fPIC

libnm_util_includedir=$(includedir)/NetworkManager

libnm_util_include_HEADERS = 		\
	dbus-dict-helpers.h		\
	nm-connection.h			\
	nm-setting.h			\
	nm-utils.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnm-util.pc

DISTCLEANFILES = libnm-util.pc

EXTRA_DIST = libnm-util.pc.in
