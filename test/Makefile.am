INCLUDES = -I${top_srcdir} -I${top_srcdir}/libnm_glib -I${top_srcdir}/utils

AM_CPPFLAGS =						\
	$(DBUS_CFLAGS)					\
	$(GTHREAD_CFLAGS)				\
	$(HAL_CFLAGS)					\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"

noinst_PROGRAMS = nmtest nminfotest nmtestdevices libnm_glib_test nm-dhcp-opt-test

nmtest_SOURCES = nmtest.c
nmtest_LDADD =	$(DBUS_LIBS) $(GTHREAD_LIBS) $(HAL_LIBS)	\
		$(top_builddir)/utils/libnmutils.la


nminfotest_SOURCES = nminfotest.c
nminfotest_LDADD =	$(DBUS_LIBS) $(GTHREAD_LIBS)	\
			$(top_builddir)/utils/libnmutils.la

nmtestdevices_SOURCES = nmtestdevices.c
nmtestdevices_LDADD =	$(DBUS_LIBS) $(GTHREAD_LIBS)	\
			$(top_builddir)/utils/libnmutils.la

libnm_glib_test_SOURCES = libnm_glib_test.c
libnm_glib_test_LDADD =	$(DBUS_LIBS) $(GTHREAD_LIBS) \
			$(top_builddir)/utils/libnmutils.la \
			../libnm_glib/libnm_glib.la


nm_dhcp_opt_test_SOURCES = nm-dhcp-opt-test.c
nm_dhcp_opt_test_LDADD =	$(DBUS_LIBS) $(GTHREAD_LIBS) \
                        	$(top_builddir)/utils/libnmutils.la

