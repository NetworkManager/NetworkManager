
namedconf_DATA = named.conf
namedconfdir = $(pkgdatadir)

EXTRA_DIST = $(namedconf_DATA)

INCLUDES = -I${top_srcdir}/utils

noinst_LTLIBRARIES = libnamed.la

libnamed_la_SOURCES = nm-named-manager.h nm-named-manager.c

libnamed_la_CPPFLAGS = $(DBUS_CFLAGS) $(GTHREAD_CFLAGS) -DNM_PKGDATADIR=\"$(pkgdatadir)\" -DNM_LOCALSTATEDIR=\"$(localstatedir)\"

libnamed_la_LIBADD = $(DBUS_LIBS) $(GTHREAD_LIBS)
