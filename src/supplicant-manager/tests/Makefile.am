SUBDIRS=certs

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/supplicant-manager \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DTEST_CERT_DIR=\"$(srcdir)/certs/\" \
	$(GLIB_CFLAGS)

noinst_PROGRAMS = test-supplicant-config

test_supplicant_config_SOURCES = \
	test-supplicant-config.c

test_supplicant_config_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

@VALGRIND_RULES@
TESTS = test-supplicant-config
