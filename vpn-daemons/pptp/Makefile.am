AUTOMAKE_OPTIONS = foreign

if WITH_GNOME
SUBDIRS = src common-gnome auth-dialog properties po
else
SUBDIRS = src
endif

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-pptp-service.conf

nmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnservice_DATA = nm-pptp-service.name

if WITH_GNOME
desktopdir = $(datadir)/applications
desktop_in_files = nm-pptp.desktop.in
desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)
@INTLTOOL_DESKTOP_RULE@

icondir = $(datadir)/icons/hicolor/48x48/apps
icon_DATA = gnome-mime-application-x-pptp-settings.png
endif

nm-pptp-service.name: $(srcdir)/nm-pptp-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' $< >$@

EXTRA_DIST = nm-pptp-service.name.in \
             $(dbusservice_DATA)  \
             $(desktop_in_files)  \
             $(icon_DATA)         \
             intltool-extract.in  \
             intltool-merge.in    \
             intltool-update.in

CLEANFILES = $(nmvpnservice_DATA) $(desktop_DATA) *~
DISTCLEANFILES = intltool-extract intltool-merge intltool-update
