SUBDIRS = cli tui

AM_CPPFLAGS = \
	-I${top_srcdir} \
	-I${top_srcdir}/libnm-util \
	-I${top_builddir}/libnm-util \
	-I${top_srcdir}/libnm-glib \
	-I${top_builddir}/libnm-glib \
	-I${top_srcdir}/include \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DNMLOCALEDIR=\"$(datadir)/locale\"

bin_PROGRAMS = nm-online

nm_online_SOURCES = nm-online.c
nm_online_CPPFLAGS = \
	-DG_LOG_DOMAIN=\""nm-online"\" \
	$(AM_CPPFLAGS)

nm_online_LDADD = \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(DBUS_LIBS) \
	$(GLIB_LIBS)
