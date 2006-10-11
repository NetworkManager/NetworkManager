SUBDIRS=icons

NULL=

INCLUDES = -I${top_srcdir} -I${top_srcdir}/utils -I${top_srcdir}/include -I${top_srcdir}/libnm-util

bin_PROGRAMS = nm-applet

nm_applet_CPPFLAGS =									\
	$(DBUS_CFLAGS)										\
	$(GTHREAD_CFLAGS)									\
	$(HAL_CFLAGS)										\
	$(DBUS_GLIB_CFLAGS)									\
	$(GLADE_CFLAGS)									\
	$(GTK_CFLAGS)										\
	$(GCONF_CFLAGS)									\
	$(LIBGNOMEUI_CFLAGS)								\
	$(PANEL_APPLET_CFLAGS)								\
	$(GNOME_KEYRING_CFLAGS)								\
	-DICONDIR=\""$(datadir)/icons"\"						\
	-DGLADEDIR=\""$(gladedir)"\"							\
	-DBINDIR=\""$(bindir)"\"								\
	-DSYSCONFDIR=\""$(sysconfdir)"\"						\
	-DAUTOSTARTDIR=\""$(datadir)/gnome/autostart"\"			\
	-DVPN_NAME_FILES_DIR=\""$(sysconfdir)/NetworkManager/VPN"\"	\
	-DDBUS_API_SUBJECT_TO_CHANGE							\
	-DG_DISABLE_DEPRECATED								\
	-DGDK_DISABLE_DEPRECATED								\
	-DGNOME_DISABLE_DEPRECATED							\
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"					\
	-DVERSION=\"$(VERSION)\"								\
	$(NULL)

if WITH_NOTIFY
nm_applet_CPPFLAGS += $(NOTIFY_CFLAGS)
endif

nm_applet_SOURCES =			\
	main.c				\
	applet.c				\
	applet.h				\
	applet-compat.c		\
	applet-compat.h		\
	applet-dbus.c			\
	applet-dbus.h			\
	applet-dbus-devices.c	\
	applet-dbus-devices.h	\
	applet-dbus-vpn.c		\
	applet-dbus-vpn.h		\
	applet-dbus-info.c		\
	applet-dbus-info.h		\
	wireless-network.c		\
	wireless-network.h		\
	nm-device.c			\
	nm-device.h			\
	other-network-dialog.c	\
	other-network-dialog.h	\
	passphrase-dialog.c		\
	passphrase-dialog.h		\
	menu-items.c			\
	menu-items.h			\
	eggtrayicon.c			\
	eggtrayicon.h			\
	vpn-password-dialog.c	\
	vpn-password-dialog.h	\
	vpn-connection.c		\
	vpn-connection.h		\
	wireless-security-manager.c	\
	wireless-security-manager.h	\
	wireless-security-option.c	\
	wireless-security-option.h	\
	wso-none.c			\
	wso-none.h			\
	wso-private.h			\
	wso-wep-ascii.c		\
	wso-wep-ascii.h		\
	wso-wep-hex.c			\
	wso-wep-hex.h			\
	wso-wep-passphrase.c	\
	wso-wep-passphrase.h	\
	wso-wpa-eap.c			\
	wso-wpa-eap.h			\
	wso-wpa-psk.c			\
	wso-wpa-psk.h			\
	wso-leap.c			\
	wso-leap.h			\
	nm-gconf-wso.c			\
	nm-gconf-wso.h			\
	nm-gconf-wso-private.h	\
	nm-gconf-wso-wep.c		\
	nm-gconf-wso-wep.h		\
	nm-gconf-wso-wpa-eap.c	\
	nm-gconf-wso-wpa-eap.h	\
	nm-gconf-wso-wpa-psk.c	\
	nm-gconf-wso-wpa-psk.h	\
	nm-gconf-wso-leap.c	\
	nm-gconf-wso-leap.h	\
	gconf-helpers.c		\
	gconf-helpers.h		\
	$(NULL)

if WITH_NOTIFY
nm_applet_SOURCES += applet-notifications.c applet-notifications.h
endif

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
	$(top_builddir)/libnm-util/libnm-util.la	\
	$(NULL)

if WITH_NOTIFY
nm_applet_LDADD += $(NOTIFY_LIBS)
endif


gladedir = $(datadir)/nm-applet
glade_DATA = applet.glade keyring.png

dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = nm-applet.conf

CLEANFILES = $(server_DATA) *.bak *.gladep

EXTRA_DIST = 				\
	$(dbusservice_DATA)		\
	$(glade_DATA)			\
	$(NULL)
