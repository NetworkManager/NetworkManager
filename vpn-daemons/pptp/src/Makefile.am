INCLUDES = -I${top_srcdir}  -I${top_srcdir}/utils -I${top_srcdir}/vpn-daemons/pptp

AM_CPPFLAGS =							\
	$(DBUS_CFLAGS)						\
	$(GTHREAD_CFLAGS)					\
	-Wall							\
	-DDBUS_API_SUBJECT_TO_CHANGE				\
	-DG_DISABLE_DEPRECATED					\
	-DBINDIR=\"$(bindir)\"					\
	-DPREFIX=\""$(prefix)"\"				\
	-DSYSCONFDIR=\""$(sysconfdir)"\"			\
	-DVERSION="\"$(VERSION)\""				\
	-DLIBDIR=\""$(libdir)"\"				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DLOCALSTATEDIR=\""$(localstatedir)"\"		 	\
	-DDATADIR=\"$(datadir)\" \
    -fPIC

bin_PROGRAMS = nm-pptp-service 

pppdplugindir = $(libdir)/pppd/2.4.3
pppdplugin_PROGRAMS = nm-pppd-plugin.so

nm_pptp_service_SOURCES =				\
				nm-pptp-service.c	\
				nm-pptp-service.h	\
				nm-utils.c		\
				nm-utils.h		\
				pppd/fsm.h		\
				pppd/ipcp.h		\
				pppd/patchlevel.h 	\
				pppd/pppd.h


nm_pptp_service_LDADD = 						\
				$(DBUS_LIBS)				\
				$(GTHREAD_LIBS)


nm_pppd_plugin_so_SOURCES = 		\
				nm-pppd-plugin.c

nm_pppd_plugin_so_LDFLAGS = 		\
				-shared 

nm_pppd_plugin_so_LDADD = 		\
				$(DBUS_LIBS)				\
				$(GTHREAD_LIBS)

CLEANFILES = *~
