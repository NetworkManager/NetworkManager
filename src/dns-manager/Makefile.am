INCLUDES = \
	-I${top_srcdir}/src/logging \
	-I${top_srcdir}/src/posix-signals \
	-I${top_srcdir}/libnm-util \
	-I${top_builddir}/libnm-util \
	-I${top_srcdir}/src \
	-I${top_srcdir}/include \
	-I${top_builddir}/include

noinst_LTLIBRARIES = libdns-manager.la

libdns_manager_la_SOURCES = \
	nm-dns-manager.h \
	nm-dns-manager.c \
	nm-dns-plugin.h \
	nm-dns-plugin.c \
	nm-dns-dnsmasq.h \
	nm-dns-dnsmasq.c \
	nm-dns-utils.h \
	nm-dns-utils.c

libdns_manager_la_CPPFLAGS = \
	$(LIBNL_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	-DNMCONFDIR=\"$(nmconfdir)\" \
	-DNMRUNDIR=\"$(nmrundir)\"

libdns_manager_la_LIBADD = \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(top_builddir)/src/posix-signals/libnm-posix-signals.la \
	$(LIBNL_LIBS) \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

