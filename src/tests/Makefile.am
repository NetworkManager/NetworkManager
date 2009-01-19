INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_srcdir)/src/dhcp-manager \
	-I$(top_srcdir)/marshallers \
	-I$(top_srcdir)/src

noinst_PROGRAMS = test-dhcp-options

test_dhcp_options_SOURCES = \
	test-dhcp-options.c \
	../nm-ip4-config.c \
	../nm-dbus-manager.c

test_dhcp_options_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(LIBNL_CFLAGS)

test_dhcp_options_LDADD = \
	$(GTHREAD_LIBS) \
	$(DBUS_LIBS) \
	$(LIBNL_LIBS) \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/src/dhcp-manager/libdhcp-manager.la

if WITH_TESTS

check-local: test-dhcp-options
	$(abs_builddir)/test-dhcp-options

endif

