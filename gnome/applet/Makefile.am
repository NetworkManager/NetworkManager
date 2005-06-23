SUBDIRS=icons

NULL=

INCLUDES = -I${top_srcdir} -I${top_srcdir}/utils

libexec_PROGRAMS = nm-applet

nm_applet_CPPFLAGS =							\
	$(DBUS_CFLAGS)							\
	$(GTHREAD_CFLAGS)						\
	$(HAL_CFLAGS)							\
	$(DBUS_GLIB_CFLAGS)						\
	$(GLADE_CFLAGS)							\
	$(GTK_CFLAGS)							\
	$(GCONF_CFLAGS)							\
	$(LIBGNOMEUI_CFLAGS)						\
	$(PANEL_APPLET_CFLAGS)						\
	$(GNOME_KEYRING_CFLAGS)						\
	-DICONDIR=\""$(datadir)/pixmaps"\"				\
	-DGLADEDIR=\""$(gladedir)"\"					\
	-DBINDIR=\""$(bindir)"\"					\
	-DSYSCONFDIR=\""$(sysconfdir)"\"				\
	-DVPN_NAME_FILES_DIR=\""$(sysconfdir)/NetworkManager/VPN"\"	\
	-DDBUS_API_SUBJECT_TO_CHANGE					\
	-DG_DISABLE_DEPRECATED						\
	-DGDK_DISABLE_DEPRECATED					\
	-DGNOME_DISABLE_DEPRECATED					\
	-DGNOMELOCALEDIR=\""$(prefix)/$(DATADIRNAME)/locale"\"		\
	-DVERSION=\"$(VERSION)\"					\
	$(NULL)

nm_applet_SOURCES =			\
	main.c				\
	applet.c			\
	applet.h			\
	applet-dbus.c			\
	applet-dbus.h			\
	applet-dbus-devices.c		\
	applet-dbus-devices.h		\
	applet-dbus-vpn.c		\
	applet-dbus-vpn.h		\
	applet-dbus-info.c		\
	applet-dbus-info.h		\
	wireless-network.c		\
	wireless-network.h		\
	nm-device.c			\
	nm-device.h			\
	other-network-dialog.c		\
	other-network-dialog.h		\
	passphrase-dialog.c		\
	passphrase-dialog.h		\
	menu-items.c			\
	menu-items.h			\
	eggtrayicon.c			\
	eggtrayicon.h			\
	vpn-password-dialog.c		\
	vpn-password-dialog.h		\
	vpn-connection.c		\
	vpn-connection.h		\
	$(NULL)

nm_applet_LDADD =						\
	$(DBUS_LIBS)						\
	$(HAL_LIBS)						\
	$(GTHREAD_LIBS)					\
	$(GLADE_LIBS)						\
	$(DBUS_GLIB_LIBS)					\
	$(PANEL_APPLET_LIBS)				\
	$(GTK_LIBS)						\
	$(GCONF_LIBS)						\
	$(LIBGNOMEUI_LIBS)					\
	$(GNOME_KEYRING_LIBS)				\
	$(top_builddir)/utils/libnmutils.la	\
	$(NULL)


gladedir = $(datadir)/NetworkManagerNotification
glade_DATA = wireless-applet.glade keyring.png

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = nm-applet.conf

CLEANFILES = $(server_DATA) *.bak *.gladep

EXTRA_DIST = 				\
	$(dbusservice_DATA)		\
	$(glade_DATA)			\
	$(NULL)
