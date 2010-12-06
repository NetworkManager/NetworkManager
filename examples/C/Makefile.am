INCLUDES = -I${top_srcdir}/libnm-util         \
           -I${top_srcdir}/libnm-glib         \
           -I${top_srcdir}/include

AM_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS)

noinst_PROGRAMS = add-connection-glib

add_connection_glib_SOURCES = add-connection-glib.c
add_connection_glib_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

EXTRA_DIST = \
	add-connection-glib.c

