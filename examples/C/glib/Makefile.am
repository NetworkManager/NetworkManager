AM_CPPFLAGS = \
	-I${top_srcdir}/include \
	-I${top_srcdir}/libnm-core \
	-I${top_builddir}/libnm-core \
	-I${top_srcdir}/libnm \
	-I${top_builddir}/libnm \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS)

noinst_PROGRAMS = \
	add-connection-dbus-glib \
	add-connection-libnm \
	get-active-connections-dbus-glib \
	list-connections-dbus-glib \
	list-connections-libnm \
	get-ap-info-libnm \
	monitor-nm-running-dbus-glib \
	monitor-nm-running-GDBus \
	monitor-nm-state-GDBus

add_connection_dbus_glib_SOURCES = add-connection-dbus-glib.c
add_connection_dbus_glib_LDADD = \
	$(top_builddir)/libnm/libnm.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

add_connection_libnm_SOURCES = add-connection-libnm.c
add_connection_libnm_LDADD = \
	$(top_builddir)/libnm/libnm.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

get_active_connections_dbus_glib_SOURCES = get-active-connections-dbus-glib.c
get_active_connections_dbus_glib_LDADD = \
	$(top_builddir)/libnm/libnm.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

list_connections_dbus_glib_SOURCES = list-connections-dbus-glib.c
list_connections_dbus_glib_LDADD = \
	$(top_builddir)/libnm/libnm.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

list_connections_libnm_SOURCES = list-connections-libnm.c
list_connections_libnm_LDADD = \
	$(top_builddir)/libnm/libnm.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

get_ap_info_libnm_SOURCES = get-ap-info-libnm.c
get_ap_info_libnm_LDADD = \
	$(top_builddir)/libnm/libnm.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

monitor_nm_running_dbus_glib_SOURCES = monitor-nm-running-dbus-glib.c
monitor_nm_running_dbus_glib_LDADD = \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

monitor_nm_running_GDBus_SOURCES = monitor-nm-running-GDBus.c
monitor_nm_running_GDBus_LDADD = \
	$(GLIB_LIBS)

monitor_nm_state_GDBus_SOURCES = monitor-nm-state-GDBus.c
monitor_nm_state_GDBus_LDADD = \
	$(GLIB_LIBS)

EXTRA_DIST = \
	add-connection-dbus-glib.c \
	add-connection-libnm.c \
	get-active-connections-dbus-glib.c \
	list-connections-dbus-glib.c \
	list-connections-libnm.c \
	get-ap-info-libnm.c \
	monitor-nm-running-dbus-glib.c \
	monitor-nm-running-GDBus.c \
	monitor-nm-state-GDBus.c

