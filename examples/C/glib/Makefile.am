AM_CPPFLAGS = \
	-I${top_srcdir}/include \
	-I$(top_builddir)/include \
	-I${top_srcdir}/libnm-core \
	-I${top_builddir}/libnm-core \
	-I${top_srcdir}/libnm \
	-I${top_builddir}/libnm \
	$(GLIB_CFLAGS)

noinst_PROGRAMS = \
	add-connection-gdbus \
	add-connection-libnm \
	get-active-connections-gdbus \
	get-ap-info-libnm \
	list-connections-gdbus \
	list-connections-libnm \
	monitor-nm-running-gdbus \
	monitor-nm-state-gdbus

add_connection_gdbus_SOURCES = add-connection-gdbus.c
add_connection_gdbus_LDADD = \
	$(GLIB_LIBS) \
	$(UUID_LIBS)

add_connection_libnm_SOURCES = add-connection-libnm.c
add_connection_libnm_LDADD = \
	$(top_builddir)/libnm/libnm.la \
	$(GLIB_LIBS)

get_active_connections_gdbus_SOURCES = get-active-connections-gdbus.c
get_active_connections_gdbus_LDADD = \
	$(GLIB_LIBS)

get_ap_info_libnm_SOURCES = get-ap-info-libnm.c
get_ap_info_libnm_LDADD = \
	$(top_builddir)/libnm/libnm.la \
	$(GLIB_LIBS)

list_connections_gdbus_SOURCES = list-connections-gdbus.c
list_connections_gdbus_LDADD = \
	$(GLIB_LIBS)

list_connections_libnm_SOURCES = list-connections-libnm.c
list_connections_libnm_LDADD = \
	$(top_builddir)/libnm/libnm.la \
	$(GLIB_LIBS)

monitor_nm_running_gdbus_SOURCES = monitor-nm-running-gdbus.c
monitor_nm_running_gdbus_LDADD = \
	$(GLIB_LIBS)

monitor_nm_state_gdbus_SOURCES = monitor-nm-state-gdbus.c
monitor_nm_state_gdbus_LDADD = \
	$(GLIB_LIBS)
