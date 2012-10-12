AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I${top_srcdir}/libnm-util \
	-I${top_builddir}/libnm-util \
	-I$(top_srcdir)/src/dnsmasq-manager \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/platform \
	$(GLIB_CFLAGS) \
	-DTESTDIR="\"$(abs_srcdir)\""

noinst_PROGRAMS = test-dnsmasq-utils

test_dnsmasq_utils_SOURCES = \
	test-dnsmasq-utils.c

test_dnsmasq_utils_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

check-local: test-dnsmasq-utils
	$(abs_builddir)/test-dnsmasq-utils

