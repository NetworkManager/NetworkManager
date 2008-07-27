INCLUDES = -I${top_srcdir}

AM_CPPFLAGS =							\
	$(DBUS_GLIB_CFLAGS)						\
	$(GTHREAD_CFLAGS)					\
	$(NM_UTILS_CFLAGS)				\
	-DDBUS_API_SUBJECT_TO_CHANGE				\
	-DG_DISABLE_DEPRECATED					\
	-DBINDIR=\"$(bindir)\"					\
	-DPREFIX=\""$(prefix)"\"				\
	-DSYSCONFDIR=\""$(sysconfdir)"\"			\
	-DNM_VERSION="\"$(VERSION)\""				\
	-DLIBDIR=\""$(libdir)"\"				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DLOCALSTATEDIR=\""$(localstatedir)"\"		 	\
	-DDATADIR=\"$(datadir)\"				\
	-DPLUGINDIR=\"$(PPPD_PLUGIN_DIR)\" 

libexec_PROGRAMS = nm-pptp-service

nm_pptp_service_SOURCES = \
				nm-pptp-service.c \
				nm-pptp-service.h

nm-pptp-pppd-service-glue.h: $(top_srcdir)/src/nm-pptp-pppd-service.xml
	dbus-binding-tool --prefix=nm_pptp_pppd_service --mode=glib-server --output=$@ $<

nm_pptp_service_LDADD = 				\
				$(DBUS_GLIB_LIBS)		\
				$(GTHREAD_LIBS)		\
				$(NM_UTILS_LIBS)

pppd_plugindir = $(PPPD_PLUGIN_DIR)
pppd_plugin_LTLIBRARIES = nm-pptp-pppd-plugin.la

nm_pptp_pppd_plugin_la_SOURCES = \
	nm-pptp-pppd-plugin.c \
	nm-ppp-status.h

nm_pptp_pppd_plugin_la_CPPFLAGS = \
	$(DBUS_GLIB_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(NM_UTILS_CFLAGS)

nm_pptp_pppd_plugin_la_LDFLAGS = -module -avoid-version

nm_pptp_pppd_plugin_la_LIBADD = \
	$(DBUS_GLIB_LIBS) \
	$(GLIB_LIBS) \
	$(NM_UTILS_LIBS)

BUILT_SOURCES = nm-pptp-pppd-service-glue.h

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = nm-pptp-pppd-service.xml

