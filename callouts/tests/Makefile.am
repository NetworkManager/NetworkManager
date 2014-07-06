if ENABLE_TESTS

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/callouts \
	-DNETWORKMANAGER_COMPILATION \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

noinst_PROGRAMS = \
	test-dispatcher-envp

####### dispatcher envp #######

test_dispatcher_envp_SOURCES = \
	test-dispatcher-envp.c

test_dispatcher_envp_LDADD = \
	$(top_builddir)/libnm/libnm.la \
	$(top_builddir)/callouts/libtest-dispatcher-envp.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

###########################################

check-local: test-dispatcher-envp
	$(abs_builddir)/test-dispatcher-envp $(abs_srcdir)

EXTRA_DIST= \
	dispatcher-old-down \
	dispatcher-old-up \
	dispatcher-old-vpn-down \
	dispatcher-old-vpn-up

endif
