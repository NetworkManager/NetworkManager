INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_srcdir)/src/dhcp-manager \
	-I$(top_builddir)/marshallers \
	-I$(top_srcdir)/src \
	-I$(top_builddir)/src

noinst_PROGRAMS = test-dhcp-options

test_dhcp_options_SOURCES = \
	test-dhcp-options.c

test_dhcp_options_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

test_dhcp_options_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/src/dhcp-manager/libdhcp-manager.la \
	$(top_builddir)/src/libtest-dhcp.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

if WITH_TESTS

check-local: test-dhcp-options
	$(abs_builddir)/test-dhcp-options

endif

