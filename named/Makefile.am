
namedconf_DATA = named.conf
namedconfdir = $(pkgdatadir)

EXTRA_DIST = $(namedconf_DATA)

noinst_LTLIBRARIES = libnamed.la

libnamed_la_SOURCES = nm-named-manager.h nm-named-manager.c

libnamed_la_CPPFLAGS = $(NM_CFLAGS) -DNM_PKGDATADIR=\"$(pkgdatadir)\" -DNM_LOCALSTATEDIR=\"$(localstatedir)\"

libnamed_la_LIBADD = $(NM_LIBS)
