if ENABLE_TESTS

INCLUDES=-I$(srcdir)/../ \
	 -I$(top_srcdir)/libnm-glib \
	 -I$(top_srcdir)/libnm-util \
	 -I$(top_builddir)/libnm-util \
	 -I$(top_srcdir)/include \
	 -I$(top_builddir)/include \
	 -I$(top_srcdir)/src/settings

noinst_PROGRAMS = check_ifnet
check_ifnet_SOURCES = test_all.c

check_ifnet_CPPFLAGS = \
	$(CHECK_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DTEST_WPA_SUPPLICANT_CONF='"$(srcdir)/wpa_supplicant.conf"'

check_ifnet_LDADD = $(top_builddir)/libnm-util/libnm-util.la \
		    $(builddir)/../lib-ifnet-io.la \
		    $(CHECK_LIBS) \
		    $(GLIB_LIBS) \
		    $(LIBM)
check-local: check_ifnet
	$(abs_builddir)/check_ifnet $(abs_srcdir) $(abs_builddir)

EXTRA_DIST = \
	hostname \
	net \
	net.all \
	nm-system-settings.conf \
	wpa_supplicant.conf \
	test_ca_cert.pem

endif
