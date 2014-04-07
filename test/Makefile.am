AM_CPPFLAGS = \
	-I${top_srcdir} \
	-I${top_srcdir}/libnm-util \
	-I${top_builddir}/libnm-util \
	-I${top_srcdir}/libnm-glib \
	-I${top_srcdir}/include \
	-I${top_builddir}/include \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DBINDIR=\"$(bindir)\" \
	-DDATADIR=\"$(datadir)\" \
	-DNMLOCALEDIR=\"$(datadir)/locale\"

bin_PROGRAMS = nm-online

noinst_PROGRAMS = libnm-glib-test

nm_online_SOURCES = nm-online.c
nm_online_CPPFLAGS = \
	-DG_LOG_DOMAIN=\""nm-online"\" \
	$(AM_CPPFLAGS)

nm_online_LDADD = \
	$(top_builddir)/libnm-glib/libnm-glib.la \
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

