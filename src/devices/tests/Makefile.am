AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/devices \
	-I$(top_srcdir)/src/systemd/ \
	-I$(top_srcdir)/src/systemd/src/systemd/ \
	-I$(top_srcdir)/src/systemd/src/libsystemd-network/ \
	-I$(top_srcdir)/src \
	-I$(top_builddir)/src \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS)

AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS = $(GLIB_LIBS) $(CODE_COVERAGE_LDFLAGS)
DEVICES_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

@GNOME_CODE_COVERAGE_RULES@

noinst_PROGRAMS = \
	test-lldp

test_lldp_SOURCES = \
	test-lldp.c \
	../nm-lldp-listener.c \
	$(top_srcdir)/src/platform/tests/test-common.c

test_lldp_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/platform/tests \
	-DSETUP=nm_linux_platform_setup

test_lldp_LDADD = $(DEVICES_LDADD)

@VALGRIND_RULES@
TESTS = \
	test-lldp
