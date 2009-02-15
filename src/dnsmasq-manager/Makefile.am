INCLUDES = \
	-I${top_srcdir}/libnm-util \
	-I${top_srcdir}/src \
	-I${top_srcdir}/include

noinst_LTLIBRARIES = libdnsmasq-manager.la

libdnsmasq_manager_la_SOURCES = \
	nm-dnsmasq-manager.h \
	nm-dnsmasq-manager.c

libdnsmasq_manager_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	-DLOCALSTATEDIR=\"$(localstatedir)\"

libdnsmasq_manager_la_LIBADD = $(GLIB_LIBS)
