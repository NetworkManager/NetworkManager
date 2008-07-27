AM_CPPFLAGS =							\
	$(DBUS_CFLAGS)						\
	$(NETWORK_MANAGER_CFLAGS)				\
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

libexec_PROGRAMS = nm-openvpn-service nm-openvpn-service-openvpn-helper

nm_openvpn_service_SOURCES =				\
				nm-openvpn-service.c	\
				nm-openvpn-service.h


nm_openvpn_service_LDADD = $(NETWORK_MANAGER_LIBS) -lnm_glib_vpn


nm_openvpn_service_openvpn_helper_SOURCES = 					\
				nm-openvpn-service-openvpn-helper.c

nm_openvpn_service_openvpn_helper_LDADD = 				\
				$(DBUS_LIBS)				\
				$(NETWORK_MANAGER_LIBS)

CLEANFILES = *~
