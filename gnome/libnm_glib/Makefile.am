INCLUDES = -I${top_srcdir}  -I${top_srcdir}/utils

lib_LTLIBRARIES=libnm_glib.la

libnm_glib_la_CPPFLAGS =			\
	$(DBUS_CFLAGS)				\
	$(GTHREAD_CFLAGS)			\
	-DDBUS_API_SUBJECT_TO_CHANGE

libnm_glib_la_SOURCES=	\
	libnm_glib.c		\
	libnm_glib.h

libnm_glib_la_LDFLAGS=	\
	$(DBUS_LIBS)		\
	$(GTHREAD_LIBS)

libnm_glib_la_LIBADD = $(top_builddir)/utils/libnmutils.la 

libnm_glib_includedir=$(includedir)/NetworkManager

libnm_glib_include_HEADERS = libnm_glib.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnm_glib.pc

DISTCLEANFILES = 		\
	libnm_glib.pc

EXTRA_DIST =			\
	libnm_glib.pc.in
