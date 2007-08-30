INCLUDES = -I${top_srcdir}                       \
	-I${top_srcdir}/include               \
	-I${top_srcdir}/utils                 \
	-I${top_srcdir}/libnm-util            \
	-I${top_srcdir}/src

noinst_LTLIBRARIES = libppp-manager.la

BUILT_SOURCES = \
	nm-ppp-marshal.h \
	nm-ppp-marshal.c

libppp_manager_la_SOURCES = \
	nm-ppp-manager.c \
	nm-ppp-manager.h \
	nm-ppp-status.h  \
	nm-ppp-marshal-main.c

libppp_manager_la_CPPFLAGS = \
	$(DBUS_CFLAGS)					\
	$(HAL_CFLAGS)					\
	-DG_DISABLE_DEPRECATED			\
	-DSYSCONFDIR=\"$(sysconfdir)\"  \
	-DLIBDIR=\"$(libdir)\"

libppp_manager_la_LIBADD = $(DBUS_LIBS) $(GLIB_LIBS)

nm_pppd_plugindir = $(libdir)
nm_pppd_plugin_PROGRAMS = nm-pppd-plugin.so

nm_pppd_plugin_so_SOURCES = \
	nm-pppd-plugin.c	\
	nm-pppd-plugin.h	\
	nm-ppp-status.h

nm_pppd_plugin_so_CPPFLAGS = $(DBUS_CFLAGS)	$(GLIB_CFLAGS) -fPIC

nm_pppd_plugin_so_LDFLAGS =	-shared
nm_pppd_plugin_so_LDADD = \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(top_builddir)/libnm-util/libnm-util.la



EXTRA_DIST = nm-ppp-marshal.list
CLEANFILES = $(BUILT_SOURCES)

nm-ppp-marshal.h: nm-ppp-marshal.list
	$(GLIB_GENMARSHAL) --prefix=nm_ppp_marshal $(srcdir)/nm-ppp-marshal.list --header > \
		xgen-gmh \
	&& (cmp -s xgen-gmh nm-ppp-marshal.h || cp xgen-gmh nm-ppp-marshal.h) \
	&& rm -f xgen-gmh xgen-gmh~

nm-ppp-marshal.c: nm-ppp-marshal.list
	$(GLIB_GENMARSHAL) --prefix=nm_ppp_marshal $(srcdir)/nm-ppp-marshal.list --body > \
		xgen-gmc \
	&& cp xgen-gmc nm-ppp-marshal.c \
	&& rm -f xgen-gmc xgen-gmc~

nm-ppp-marshal-main.c: nm-ppp-marshal.c nm-ppp-marshal.h

