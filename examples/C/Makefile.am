INCLUDES = -I${top_srcdir}/libnm-util         \
           -I${top_srcdir}/libnm-glib         \
           -I${top_srcdir}/include

AM_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS)

noinst_PROGRAMS = \
	add-connection-dbus-glib \
	add-connection-libnm-glib \
	get-active-connections-dbus-glib \
	list-connections-dbus-glib \
	list-connections-libnm-glib \
	get-ap-info-libnm-glib

add_connection_dbus_glib_SOURCES = add-connection-dbus-glib.c
add_connection_dbus_glib_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

add_connection_libnm_glib_SOURCES = add-connection-libnm-glib.c
add_connection_libnm_glib_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

get_active_connections_dbus_glib_SOURCES = get-active-connections-dbus-glib.c
get_active_connections_dbus_glib_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

list_connections_dbus_glib_SOURCES = list-connections-dbus-glib.c
list_connections_dbus_glib_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

list_connections_libnm_glib_SOURCES = list-connections-libnm-glib.c
list_connections_libnm_glib_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

get_ap_info_libnm_glib_SOURCES = get-ap-info-libnm-glib.c
get_ap_info_libnm_glib_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

EXTRA_DIST = \
	add-connection-dbus-glib.c \
	add-connection-libnm-glib.c \
	get-active-connections-dbus-glib.c \
	list-connections-dbus-glib.c \
	list-connections-libnm-glib.c \
	get-ap-info-libnm-glib.c

