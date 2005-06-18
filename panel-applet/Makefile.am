SUBDIRS=icons

NULL=
NOTIFICATION_ICON_SOURCE=@NOTIFICATION_ICON_SRC@

INCLUDES = -I${top_srcdir}

noinst_LTLIBRARIES = libnm_notification_applet.la

gladedir = $(datadir)/NetworkManagerNotification
glade_DATA = wireless-applet.glade

libnm_notification_applet_la_CPPFLAGS = 		\
	$(DBUS_CFLAGS)					\
	$(GTHREAD_CFLAGS)				\
	$(HAL_CFLAGS)					\
	$(DBUS_GLIB_CFLAGS)				\
	$(GLADE_CFLAGS)					\
	$(GTK_CFLAGS)					\
	$(GCONF_CFLAGS)					\
	$(LIBGNOMEUI_CFLAGS)				\
	$(PANEL_APPLET_CFLAGS)				\
	-DICONDIR=\""$(datadir)/pixmaps"\"		\
	-DGLADEDIR=\""$(gladedir)"\"			\
	-DDBUS_API_SUBJECT_TO_CHANGE			\
	-DG_DISABLE_DEPRECATED				\
	-DGDK_DISABLE_DEPRECATED			\
	-DGNOME_DISABLE_DEPRECATED			\
	-DGNOMELOCALEDIR=\""$(prefix)/$(DATADIRNAME)/locale"\"	\
	-DVERSION=\"$(VERSION)\" \
	$(NULL)

libnm_notification_applet_la_SOURCES =	\
	NMWirelessApplet.c		\
	NMWirelessApplet.h		\
	NMWirelessAppletDbus.c		\
	NMWirelessAppletDbus.h		\
	NMWirelessAppletOtherNetworkDialog.c	\
	NMWirelessAppletOtherNetworkDialog.h	\
	menu-info.c			\
	menu-info.h			\
	$(NULL)

libnm_notification_applet_la_SOURCES +=	\
	eggtrayicon.c			\
	eggtrayicon.h			

libnm_notification_applet_la_LIBADD =	\
	$(DBUS_LIBS)			\
	$(HAL_LIBS)			\
	$(GTHREAD_LIBS)			\
	$(GLADE_LIBS)			\
	$(DBUS_GLIB_LIBS)		\
	$(PANEL_APPLET_LIBS)		\
	$(GTK_LIBS)			\
	$(GCONF_LIBS)			\
	$(LIBGNOMEUI_LIBS)		\
	$(NULL)

libexec_PROGRAMS = NetworkManagerNotification

NetworkManagerNotification_CFLAGS = $(libnm_notification_applet_la_CPPFLAGS)
NetworkManagerNotification_SOURCES = main.c
NetworkManagerNotification_LDADD = ./libnm_notification_applet.la

CLEANFILES = $(server_DATA) *.bak *.gladep

EXTRA_DIST = 				\
	$(glade_DATA)			\
	$(NULL)

