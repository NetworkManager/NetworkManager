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

uidir = $(datadir)/gnome-2.0/ui
ui_DATA = NMWirelessApplet.xml

gladedir = $(datadir)/NMWirelessApplet
glade_DATA = wireless-applet.glade

pixmapdir = $(datadir)/pixmaps/NMWirelessApplet
pixmap_DATA =				\
	no-networkmanager.png	\
	no-link-0.png			\
	wired.png				\
	wireless.png			\
	broken-0.png			\
	signal-1-40.png		\
	signal-41-60.png		\
	signal-61-80.png		\
	signal-81-100.png		\
	wireless-applet.png		\
	connect-0.png			\
	connect-1.png			\
	connect-2.png			\
	connect-3.png			\
	keyring.png			\
	$(NULL)

CLEANFILES = $(server_DATA) *.bak *.gladep

EXTRA_DIST = 				\
	$(pixmap_DATA)			\
	$(ui_DATA)			\
	$(glade_DATA)			\
	$(NULL)

