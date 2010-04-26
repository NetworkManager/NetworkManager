INCLUDES = \
	-I${top_srcdir}/src/logging \
	-I${top_srcdir}/libnm-util \
	-I${top_srcdir}/src \
	-I${top_srcdir}/include

noinst_LTLIBRARIES = libnamed-manager.la

libnamed_manager_la_SOURCES = nm-named-manager.h nm-named-manager.c

libnamed_manager_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DNM_PKGDATADIR=\"$(pkgdatadir)\" \
	-DNM_LOCALSTATEDIR=\"$(localstatedir)\"

libnamed_manager_la_LIBADD = \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

