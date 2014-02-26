AM_CPPFLAGS = \
	-I${top_srcdir}/include \
	-I${top_builddir}/include \
	$(DBUS_CFLAGS) \
	$(QT_CFLAGS)

noinst_PROGRAMS = \
	add-connection-wired \
	list-connections \
	change-ipv4-addresses \
	monitor-nm-running

add_connection_wired_SOURCES = add-connection-wired.cpp
add_connection_wired_LDADD = \
	$(DBUS_LIBS) \
	$(QT_LIBS)

list_connections_SOURCES = list-connections.cpp
list_connections_LDADD = \
	$(DBUS_LIBS) \
	$(QT_LIBS)

change_ipv4_addresses_SOURCES = change-ipv4-addresses.cpp
change_ipv4_addresses_LDADD = \
	$(DBUS_LIBS) \
	$(QT_LIBS)

monitor_nm_running_SOURCES = monitor-nm-running.cpp
monitor_nm_running_LDADD = \
	$(DBUS_LIBS) \
	$(QT_LIBS)

monitor-nm-running.moc: monitor-nm-running.cpp
	$(AM_V_GEN) $(MOC) -i $< -o $@

BUILT_SOURCES = \
	monitor-nm-running.moc

EXTRA_DIST = \
	add-connection-wired.cpp \
	list-connections.cpp \
	change-ipv4-addresses.cpp \
	monitor-nm-running.cpp

CLEANFILES = $(BUILT_SOURCES)

