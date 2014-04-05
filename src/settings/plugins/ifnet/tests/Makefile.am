if ENABLE_TESTS

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS= \
	-I$(srcdir)/../ \
	-I$(top_srcdir)/libnm-glib \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/config \
	-I$(top_srcdir)/src/logging \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/src/platform \
	-DG_LOG_DOMAIN=\""NetworkManager-ifnet"\" \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(CHECK_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(POLKIT_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) \
	-DTEST_WPA_SUPPLICANT_CONF='"$(srcdir)/wpa_supplicant.conf"' \
	-DSYSCONFDIR=\"nonexistent\"

noinst_PROGRAMS = check_ifnet
check_ifnet_SOURCES = \
	test_all.c \
	../connection_parser.c \
	../net_parser.c \
	../net_utils.c \
	../wpa_parser.c \
	../errors.c

check_ifnet_LDFLAGS = \
	$(CODE_COVERAGE_LDFLAGS)

check_ifnet_LDADD = $(top_builddir)/src/libNetworkManager.la

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
