SUBDIRS=icons

NULL=
NOTIFICATION_ICON_SOURCE=@NOTIFICATION_ICON_SRC@

INCLUDES = 							\
	$(NM_CFLAGS)						\
	$(GLADE_CFLAGS)						\
	$(DBUS_CFLAGS)						\
	$(DBUS_GLIB_CFLAGS)					\
	$(GTK_CFLAGS)						\
	$(GCONF_CFLAGS)						\
	$(LIBGNOMEUI_CFLAGS)					\
	$(PANEL_APPLET_CFLAGS)					\
	-DICONDIR=\""$(datadir)/pixmaps"\"			\
	-DG_DISABLE_DEPRECATED					\
	-DGDK_DISABLE_DEPRECATED				\
	-DGNOME_DISABLE_DEPRECATED				\
	-DGNOMELOCALEDIR=\""$(prefix)/$(DATADIRNAME)/locale"\"	\
	$(NULL)

noinst_LTLIBRARIES = libnm_notification_applet.la

libnm_notification_applet_la_SOURCES =	\
	NMWirelessApplet.c		\
	NMWirelessApplet.h		\
	NMWirelessAppletDbus.c		\
	NMWirelessAppletDbus.h		\
	menu-info.c			\
	menu-info.h			\
	gtkcellview.c			\
	gtkcellview.h			\
	gtkcellrendererprogress.c	\
	gtkcellrendererprogress.h	\
	$(NULL)

libnm_notification_applet_la_SOURCES +=	\
	eggtrayicon.c			\
	eggtrayicon.h			

libnm_notification_applet_la_LIBADD =	\
	$(NM_LIBS)			\
	$(GLADE_LIBS)			\
	$(DBUS_LIBS)			\
	$(DBUS_GLIB_LIBS)		\
	$(PANEL_APPLET_LIBS)		\
	$(GTK_LIBS)			\
	$(GCONF_LIBS)			\
	$(LIBGNOMEUI_LIBS)		\
	$(NULL)

libexec_PROGRAMS = NetworkManagerNotification

NetworkManagerNotification_SOURCES = main.c
NetworkManagerNotification_LDADD = ./libnm_notification_applet.la

gladedir = $(datadir)/NetworkManagerNotification
glade_DATA = essid.glade

CLEANFILES = $(server_DATA) *.bak *.gladep

EXTRA_DIST = 				\
	$(glade_DATA)			\
	$(NULL)

