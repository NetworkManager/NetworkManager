AM_CPPFLAGS = \
	-I${top_srcdir} \
	-I${top_srcdir}/shared \
	-I${top_builddir}/shared \
	-I${top_srcdir}/src \
	-I${top_builddir}/src \
	-I${top_srcdir}/libnm-core \
	-I${top_builddir}/libnm-core \
	-I${srcdir}/.. \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	$(GLIB_CFLAGS) \
	$(GUDEV_CFLAGS) \
	$(LIBNL_CFLAGS)

if REQUIRE_ROOT_TESTS
AM_CPPFLAGS += -DREQUIRE_ROOT_TESTS=1
endif

PLATFORM_SOURCES = \
	../nm-platform.c \
	../nm-fake-platform.c \
	../nm-linux-platform.c
TEST_SOURCES = \
	test-common.c \
	test-common.h \
	$(PLATFORM_SOURCES)
AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS = $(GLIB_LIBS) $(GUDEV_LIBS) $(LIBNL_LIBS) $(CODE_COVERAGE_LDFLAGS)
PLATFORM_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

@GNOME_CODE_COVERAGE_RULES@

noinst_PROGRAMS = \
	monitor \
	test-link-fake \
	test-link-linux \
	test-address-fake \
	test-address-linux \
	test-general \
	test-nmp-object \
	test-route-fake \
	test-route-linux \
	test-cleanup-fake \
	test-cleanup-linux

EXTRA_DIST = test-common.h

monitor_SOURCES = monitor.c $(PLATFORM_SOURCES)
monitor_LDADD = $(PLATFORM_LDADD)

test_link_fake_SOURCES = $(TEST_SOURCES) test-link.c
test_link_fake_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DSETUP=nm_fake_platform_setup \
	-DKERNEL_HACKS=0
test_link_fake_LDADD = $(PLATFORM_LDADD)

test_link_linux_SOURCES = $(TEST_SOURCES) test-link.c
test_link_linux_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DSETUP=nm_linux_platform_setup \
	-DKERNEL_HACKS=1
test_link_linux_LDADD = $(PLATFORM_LDADD)

test_address_fake_SOURCES = $(TEST_SOURCES) test-address.c
test_address_fake_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DSETUP=nm_fake_platform_setup \
	-DKERNEL_HACKS=0
test_address_fake_LDADD = $(PLATFORM_LDADD)

test_address_linux_SOURCES = $(TEST_SOURCES) test-address.c
test_address_linux_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DSETUP=nm_linux_platform_setup \
	-DKERNEL_HACKS=1
test_address_linux_LDADD = $(PLATFORM_LDADD)

test_route_fake_SOURCES = $(TEST_SOURCES) test-route.c
test_route_fake_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DSETUP=nm_fake_platform_setup \
	-DKERNEL_HACKS=0
test_route_fake_LDADD = $(PLATFORM_LDADD)

test_route_linux_SOURCES = $(TEST_SOURCES) test-route.c
test_route_linux_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DSETUP=nm_linux_platform_setup \
	-DKERNEL_HACKS=1
test_route_linux_LDADD = $(PLATFORM_LDADD)

test_cleanup_fake_SOURCES = $(TEST_SOURCES) test-cleanup.c
test_cleanup_fake_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DSETUP=nm_fake_platform_setup \
	-DKERNEL_HACKS=0
test_cleanup_fake_LDADD = $(PLATFORM_LDADD)

test_cleanup_linux_SOURCES = $(TEST_SOURCES) test-cleanup.c
test_cleanup_linux_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DSETUP=nm_linux_platform_setup \
	-DKERNEL_HACKS=1
test_cleanup_linux_LDADD = $(PLATFORM_LDADD)

test_nmp_object_SOURCES = \
	test-nmp-object.c
test_nmp_object_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

test_general_SOURCES = \
	test-general.c
test_general_LDADD = \
	$(top_builddir)/src/libNetworkManager.la


@VALGRIND_RULES@
TESTS = \
	test-address-fake \
	test-address-linux \
	test-cleanup-fake \
	test-cleanup-linux \
	test-general \
	test-link-fake \
	test-link-linux \
	test-nmp-object \
	test-route-fake \
	test-route-linux

