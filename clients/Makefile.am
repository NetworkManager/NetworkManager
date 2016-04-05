SUBDIRS = cli tui

AM_CPPFLAGS = \
	-I${top_srcdir}/shared \
	-I$(top_builddir)/shared \
	-I${top_srcdir}/libnm-core \
	-I${top_builddir}/libnm-core \
	-I${top_srcdir}/libnm \
	-I${top_builddir}/libnm \
	$(GLIB_CFLAGS) \
	-DNMLOCALEDIR=\"$(datadir)/locale\"

bin_PROGRAMS = nm-online

nm_online_SOURCES = nm-online.c
nm_online_CPPFLAGS = \
	-DG_LOG_DOMAIN=\""nm-online"\" \
	$(AM_CPPFLAGS)

nm_online_LDADD = \
	$(top_builddir)/libnm/libnm.la \
	$(GLIB_LIBS)
