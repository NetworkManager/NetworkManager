INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_srcdir)/callouts

noinst_PROGRAMS = \
	test-dispatcher-envp

####### dispatcher envp #######

test_dispatcher_envp_SOURCES = \
	test-dispatcher-envp.c

test_dispatcher_envp_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

test_dispatcher_envp_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(top_builddir)/callouts/libtest-dispatcher-envp.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

###########################################

if WITH_TESTS

check-local: test-dispatcher-envp
	$(abs_builddir)/test-dispatcher-envp $(abs_srcdir)

endif

EXTRA_DIST= \
	dispatcher-old-down \
	dispatcher-old-up \
	dispatcher-old-vpn-down \
	dispatcher-old-vpn-up

