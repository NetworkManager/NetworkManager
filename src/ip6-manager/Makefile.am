INCLUDES = \
	-I${top_srcdir} \
	-I${top_srcdir}/include \
	-I${top_builddir}/marshallers \
	-I${top_srcdir}/libnm-util \
	-I${top_srcdir}/src/logging \
	-I${top_srcdir}/src

noinst_LTLIBRARIES = libip6-manager.la

libip6_manager_la_SOURCES = \
	nm-ip6-manager.c \
	nm-ip6-manager.h

libip6_manager_la_CPPFLAGS = \
	$(LIBNL_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DG_DISABLE_DEPRECATED

libip6_manager_la_LIBADD = \
	$(top_builddir)/marshallers/libmarshallers.la \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(LIBNL_LIBS) \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

