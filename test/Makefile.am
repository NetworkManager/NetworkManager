SUBDIRS=libnm-util

INCLUDES = -I${top_srcdir}                    \
           -I${top_srcdir}/gnome/libnm_glib   \
           -I${top_srcdir}/utils              \
           -I${top_srcdir}/include

AM_CPPFLAGS =						\
	$(DBUS_CFLAGS)					\
	$(GTHREAD_CFLAGS)				\
	$(HAL_CFLAGS)					\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"

noinst_PROGRAMS = nm-tool nminfotest nmtestdevices libnm_glib_test

noinst_LTLIBRARIES=libtest-common.la

nm_tool_SOURCES = nm-tool.c
nm_tool_LDADD =	$(DBUS_LIBS) $(GTHREAD_LIBS) $(HAL_LIBS)	\
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
			../gnome/libnm_glib/libnm_glib.la


libtest_common_la_SOURCES= \
	test-common.c         \
	test-common.h

libtest_common_la_CPPFLAGS =			\
	$(GLIB_CFLAGS)					\
	-DG_DISABLE_DEPRECATED

libtest_common_la_LIBADD = $(GLIB_LIBS)

