INCLUDES = -I${top_srcdir}                    \
           -I${top_srcdir}/libnm-util         \
           -I${top_builddir}/libnm-util         \
           -I${top_srcdir}/libnm-glib         \
           -I${top_srcdir}/include            \
	   -I${top_builddir}/include

AM_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DBINDIR=\"$(bindir)\" \
	-DDATADIR=\"$(datadir)\" \
	-DNMLOCALEDIR=\"$(datadir)/locale\"

bin_PROGRAMS = nm-tool nm-online

noinst_PROGRAMS = libnm-glib-test

nm_tool_SOURCES = nm-tool.c
nm_tool_LDADD = \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

nm_online_SOURCES = nm-online.c
nm_online_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

libnm_glib_test_SOURCES = libnm-glib-test.c
libnm_glib_test_CFLAGS = \
	-Wno-deprecated-declarations \
	-Wno-deprecated
libnm_glib_test_LDADD = \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)

