INCLUDES = \
	-I${top_srcdir} \
	-I${top_srcdir}/include \
	-I${top_srcdir}/libnm-util \
	-I${top_srcdir}/src \
	-I${top_builddir}/src/marshallers

noinst_LTLIBRARIES = libppp-manager.la

libppp_manager_la_SOURCES = \
	nm-ppp-manager.c \
	nm-ppp-manager.h \
	nm-ppp-status.h

libppp_manager_la_CPPFLAGS = \
	$(DBUS_CFLAGS)					\
	$(HAL_CFLAGS)					\
	-DG_DISABLE_DEPRECATED			\
	-DSYSCONFDIR=\"$(sysconfdir)\"  \
	-DLIBDIR=\"$(libdir)\"

libppp_manager_la_LIBADD = \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(top_builddir)/src/marshallers/libmarshallers.la

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

CLEANFILES = $(BUILT_SOURCES)

