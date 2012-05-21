INCLUDES = \
	-I${top_srcdir}/libnm-util \
	-I${top_srcdir}/src/logging \
	-I${top_srcdir}/src/posix-signals \
	-I${top_srcdir}/src \
	-I${top_srcdir}/include

noinst_LTLIBRARIES = libdnsmasq-manager.la

libdnsmasq_manager_la_SOURCES = \
	nm-dnsmasq-manager.h \
	nm-dnsmasq-manager.c

libdnsmasq_manager_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	-DLOCALSTATEDIR=\"$(localstatedir)\"

libdnsmasq_manager_la_LIBADD = \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(top_builddir)/src/posix-signals/libnm-posix-signals.la \
	$(GLIB_LIBS)
