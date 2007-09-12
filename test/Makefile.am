SUBDIRS=test-common libnm-util

INCLUDES = -I${top_srcdir}                    \
           -I${top_srcdir}/libnm-util         \
           -I${top_srcdir}/libnm-glib         \
           -I${top_srcdir}/gnome/libnm_glib   \
           -I${top_srcdir}/include

AM_CPPFLAGS =						\
	$(DBUS_CFLAGS)					\
	$(GTHREAD_CFLAGS)				\
	$(HAL_CFLAGS)					\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DBINDIR=\"$(bindir)\"			\
	-DNM_RUN_DIR=\"$(rundir)\" \
	-DDATADIR=\"$(datadir)\"

noinst_PROGRAMS = nm-tool \
                  nm-online \
                  nmtestdevices \
                  libnm_glib_test

nm_tool_SOURCES = nm-tool.c
nm_tool_LDADD =	$(DBUS_LIBS) $(GTHREAD_LIBS) $(HAL_LIBS)	\
		$(top_builddir)/libnm-glib/libnm_glib.la \
		$(top_builddir)/libnm-util/libnm-util.la

nm_online_SOURCES = nm-online.c
nm_online_LDADD =	$(DBUS_LIBS) $(GTHREAD_LIBS) $(HAL_LIBS)	\
		$(top_builddir)/libnm-util/libnm-util.la

nmtestdevices_SOURCES = nmtestdevices.c
nmtestdevices_LDADD =	$(DBUS_LIBS) $(GTHREAD_LIBS)	\
			$(top_builddir)/libnm-util/libnm-util.la

libnm_glib_test_SOURCES = libnm_glib_test.c
libnm_glib_test_LDADD =	$(DBUS_LIBS) $(GTHREAD_LIBS) \
			$(top_builddir)/libnm-glib/libnm_glib.la \
			$(top_builddir)/libnm-util/libnm-util.la

nm_supplicant_test_SOURCES = nm-supplicant-test.c
nm_supplicant_test_LDADD = $(GLIB_LIBS) $(GTHREAD_LIBS)
