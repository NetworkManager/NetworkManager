INCLUDES = -I${top_srcdir}/include

AM_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(QT_CFLAGS)

noinst_PROGRAMS = \
	add-connection-wired

add_connection_wired_SOURCES = add-connection-wired.cpp
add_connection_wired_LDADD = \
	$(DBUS_LIBS) \
	$(QT_LIBS)

EXTRA_DIST = \
	add-connection-wired.cpp

