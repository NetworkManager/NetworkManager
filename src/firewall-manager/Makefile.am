INCLUDES = \
	-I${top_srcdir}/src \
	-I${top_srcdir}/src/logging \
	-I${top_srcdir}/include \
	-I${top_srcdir}/libnm-util

noinst_LTLIBRARIES = libfirewall-manager.la

libfirewall_manager_la_SOURCES = \
	nm-firewall-manager.h \
	nm-firewall-manager.c

libfirewall_manager_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DNM_PKGDATADIR=\"$(pkgdatadir)\" \
	-DNM_LOCALSTATEDIR=\"$(localstatedir)\"

libfirewall_manager_la_LIBADD = \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

