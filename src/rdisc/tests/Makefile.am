AM_CPPFLAGS = \
	-I${top_srcdir} \
	-I$(top_srcdir)/include \
	-I${top_srcdir}/src \
	-I${top_srcdir}/src/platform \
	-I${top_srcdir}/libnm-core \
	-I${top_builddir}/libnm-core \
	-I${srcdir}/.. \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	$(LIBNDP_CFLAGS)

AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS = \
	$(GLIB_LIBS) \
	$(DBUS_LIBS) \
	$(CODE_COVERAGE_LDFLAGS)

@GNOME_CODE_COVERAGE_RULES@

noinst_PROGRAMS = test-rdisc-linux test-rdisc-fake

test_rdisc_linux_SOURCES = \
	test-rdisc-linux.c
test_rdisc_linux_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

test_rdisc_fake_SOURCES = \
	test-rdisc-fake.c
test_rdisc_fake_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

@VALGRIND_RULES@
TESTS = test-rdisc-fake

