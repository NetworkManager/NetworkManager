INCLUDES = -I${top_srcdir}/include

AM_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(QT_CFLAGS)

noinst_PROGRAMS = \
	add-connection-wired \
	list-connections

add_connection_wired_SOURCES = add-connection-wired.cpp
add_connection_wired_LDADD = \
	$(DBUS_LIBS) \
	$(QT_LIBS)

list_connections_SOURCES = list-connections.cpp
list_connections_LDADD = \
	$(DBUS_LIBS) \
	$(QT_LIBS)

EXTRA_DIST = \
	add-connection-wired.cpp \
	list-connections.cpp

