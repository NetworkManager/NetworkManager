INCLUDES = -I${top_srcdir}                  \
           -I${top_srcdir}/utils            \
           -I${top_srcdir}/vpn-daemons/pptp

AM_CPPFLAGS =							\
	$(DBUS_CFLAGS)						\
	$(GTHREAD_CFLAGS)					\
	$(PPPD_CFLAGS)							\
	-Wall							\
	-DDBUS_API_SUBJECT_TO_CHANGE				\
	-DG_DISABLE_DEPRECATED					\
	-DBINDIR=\"$(bindir)\"					\
	-DPREFIX=\""$(prefix)"\"				\
	-DSYSCONFDIR=\""$(sysconfdir)"\"			\
	-DNM_VERSION="\"$(VERSION)\""				\
	-DLIBDIR=\""$(libdir)"\"				\
	-DLIBEXECDIR=\""$(libexecdir)"\"			\
	-DLOCALSTATEDIR=\""$(localstatedir)"\"		 	\
	-DDATADIR=\"$(datadir)\" \
    -fPIC

bin_PROGRAMS = nm-ppp-starter

pppdplugindir = $(PPPD_PLUGIN_DIR)
pppdplugin_PROGRAMS = nm-pppd-plugin.so

nm_ppp_starter_SOURCES =			\
				nm-ppp-starter.c	\
				nm-ppp-starter.h	\
				nm-utils.c			\
				nm-utils.h			\
				pppd/fsm.h			\
				pppd/ipcp.h			\
				pppd/patchlevel.h 	\
				pppd/pppd.h


nm_ppp_starter_LDADD = 				\
				$(DBUS_LIBS)		\
				$(GTHREAD_LIBS)            

nm_pppd_plugin_so_SOURCES = 		\
				nm-pppd-plugin.c 	\
				nm-pppd-plugin.h  	\
				nm-ppp-starter.h

nm_pppd_plugin_so_LDFLAGS = 		\
				-shared 

nm_pppd_plugin_so_LDADD = 		\
				$(DBUS_LIBS)	\
				$(GTHREAD_LIBS)

CLEANFILES = *~
