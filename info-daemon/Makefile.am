
INCLUDES = -I${top_srcdir}

AM_CPPFLAGS =								\
	$(NM_CFLAGS)							\
	$(GTK_CFLAGS)							\
	$(GDK_PIXBUF_CFLAGS)						\
	$(GLADE_CFLAGS)							\
	$(GCONF_CFLAGS)							\
	$(LIBGNOMEUI_CFLAGS)						\
	-Wall								\
	-DDBUS_API_SUBJECT_TO_CHANGE					\
	-DG_DISABLE_DEPRECATED						\
	-DGTK_DISABLE_DEPRECATED					\
	-DGLADEDIR=\""$(datadir)/NetworkManagerInfo/glade"\"		\
	-DBINDIR=\"$(bindir)\"						\
	-DPREFIX=\""$(prefix)"\"					\
	-DSYSCONFDIR=\""$(sysconfdir)"\"				\
	-DVERSION="\"$(VERSION)\""					\
	-DLIBDIR=\""$(libdir)"\"					\
	-DLIBEXECDIR=\""$(libexecdir)"\"				\
	-DDATADIR=\"$(datadir)\"

bin_PROGRAMS = NetworkManagerInfo

NetworkManagerInfo_SOURCES =	NetworkManagerInfo.h		\
				NetworkManagerInfo.c				\
				NetworkManagerInfoDbus.h				\
				NetworkManagerInfoDbus.c				\
				NetworkManagerInfoPassphraseDialog.c	\
				NetworkManagerInfoPassphraseDialog.h	\
				NetworkManagerInfoNetworksDialog.c		\
				NetworkManagerInfoNetworksDialog.h

NetworkManagerInfo_LDADD = $(NM_LIBS) 		\
			   $(GLADE_LIBS) 	\
			   $(GCONF_LIBS) 	\
			   $(GTK_LIBS) 		\
			   $(GDK_PIXBUF_LIBS)   \
			   $(LIBGNOMEUI_LIBS)	

gladedir = $(datadir)/NetworkManagerInfo/glade
glade_DATA = passphrase.glade keyring.png networks.glade

dbusservicedir=$(DBUS_SYS_DIR)
dbusservice_DATA = NetworkManagerInfo.conf

EXTRA_DIST = $(glade_DATA) $(dbusservice_DATA)

