INCLUDES = -I${top_srcdir}  -I${top_srcdir}/utils -I${top_srcdir}/vpn-daemons/pptp

AM_CPPFLAGS =							\
	$(DBUS_CFLAGS)						\
	$(GTHREAD_CFLAGS)					\
	$(NETWORK_MANAGER_CFLAGS)				\
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
	-DDATADIR=\"$(datadir)\"

bin_PROGRAMS = nm-pptp-service nm-pptp-service-pppd-plugin.so

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
				$(GTHREAD_LIBS)				\
				$(NETWORK_MANAGER_LIBS)


nm_pptp_service_pppd_plugin_so_SOURCES = 		\
				nm-pptp-service-pppd-plugin.c

nm_pptp_service_pppd_plugin_so_LDFLAGS = 		\
                -shared

nm_pptp_service_pppd_plugin_so_LDADD = 		\
				$(DBUS_LIBS)				\
				$(GTHREAD_LIBS)				\
				$(NETWORK_MANAGER_LIBS)

CLEANFILES = *~
