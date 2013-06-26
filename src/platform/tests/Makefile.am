AM_CPPFLAGS = \
	-I${top_srcdir} \
	-I${top_srcdir}/src \
	-I${top_srcdir}/src/logging \
	-I${top_srcdir}/libnm-util \
	-I${srcdir}/.. \
	$(GLIB_CFLAGS) \
	$(GUDEV_CFLAGS) \
	$(LIBNL_CFLAGS)

PLATFORM_SOURCES = \
	../nm-platform.c \
	../nm-fake-platform.c \
	../nm-linux-platform.c
TEST_SOURCES = $(PLATFORM_SOURCES) test-common.c test-common.h
AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS = $(GLIB_LIBS) $(GUDEV_LIBS) $(LIBNL_LIBS) $(CODE_COVERAGE_LDFLAGS)
PLATFORM_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

@GNOME_CODE_COVERAGE_RULES@

noinst_PROGRAMS = \
	dump \
	monitor \
	platform \
	test-link-fake \
	test-link-linux \
	test-address-fake \
	test-address-linux \
	test-route-fake \
	test-route-linux \
	test-cleanup-fake \
	test-cleanup-linux

EXTRA_DIST = test-common.h

monitor_SOURCES = monitor.c $(PLATFORM_SOURCES)
monitor_CPPFLAGS = $(AM_CPPFLAGS)
monitor_LDADD = $(PLATFORM_LDADD)

dump_SOURCES = dump.c $(PLATFORM_SOURCES)
dump_CPPFLAGS = $(AM_CPPFLAGS)
dump_LDADD = $(PLATFORM_LDADD)

platform_SOURCES = platform.c $(PLATFORM_SOURCES)
platform_CPPFLAGS = $(AM_CPPFLAGS)
platform_LDADD = $(PLATFORM_LDADD)

test_link_fake_SOURCES = test-link.c $(TEST_SOURCES)
test_link_fake_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DSETUP=nm_fake_platform_setup \
	-DKERNEL_HACKS=0
test_link_fake_LDADD = $(PLATFORM_LDADD)

test_link_linux_SOURCES = test-link.c $(TEST_SOURCES)
test_link_linux_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DSETUP=nm_linux_platform_setup \
	-DKERNEL_HACKS=1
test_link_linux_LDADD = $(PLATFORM_LDADD)

test_address_fake_SOURCES = test-address.c $(TEST_SOURCES)
test_address_fake_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DSETUP=nm_fake_platform_setup \
	-DKERNEL_HACKS=0
test_address_fake_LDADD = $(PLATFORM_LDADD)

test_address_linux_SOURCES = test-address.c $(TEST_SOURCES)
test_address_linux_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DSETUP=nm_linux_platform_setup \
	-DKERNEL_HACKS=1
test_address_linux_LDADD = $(PLATFORM_LDADD)

test_route_fake_SOURCES = test-route.c $(TEST_SOURCES)
test_route_fake_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DSETUP=nm_fake_platform_setup \
	-DKERNEL_HACKS=0
test_route_fake_LDADD = $(PLATFORM_LDADD)

test_route_linux_SOURCES = test-route.c $(TEST_SOURCES)
test_route_linux_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DSETUP=nm_linux_platform_setup \
	-DKERNEL_HACKS=1
test_route_linux_LDADD = $(PLATFORM_LDADD)

test_cleanup_fake_SOURCES = test-cleanup.c $(TEST_SOURCES)
test_cleanup_fake_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DSETUP=nm_fake_platform_setup \
	-DKERNEL_HACKS=0
test_cleanup_fake_LDADD = $(PLATFORM_LDADD)

test_cleanup_linux_SOURCES = test-cleanup.c $(TEST_SOURCES)
test_cleanup_linux_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-DSETUP=nm_linux_platform_setup \
	-DKERNEL_HACKS=1
test_cleanup_linux_LDADD = $(PLATFORM_LDADD)

# Unfortunately, we cannot run nm-linux-platform-test as an automatic test
# program by default, as it requires root access and modifies kernel
# configuration.
#
# However, we can check whether the fake platform fakes platform behavior
# correctly.

@VALGRIND_RULES@
TESTS = ./test-link-fake ./test-address-fake ./test-route-fake ./test-cleanup-fake
ROOTTESTS = ./test-link-linux ./test-address-linux ./test-route-linux ./test-cleanup-linux

# If explicitly enabled, we can run the root tests
if RUN_ROOT_TESTS
TESTS += $(ROOTTESTS)
endif
