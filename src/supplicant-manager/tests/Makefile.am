SUBDIRS=certs

AM_CPPFLAGS = \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/supplicant-manager \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	-DTEST_CERT_DIR=\"$(srcdir)/certs/\" \
	$(GLIB_CFLAGS)

noinst_PROGRAMS = test-supplicant-config

test_supplicant_config_SOURCES = \
	test-supplicant-config.c

test_supplicant_config_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

@VALGRIND_RULES@
TESTS = test-supplicant-config
