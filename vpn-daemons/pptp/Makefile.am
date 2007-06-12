AUTOMAKE_OPTIONS = foreign

if WITH_GNOME
SUBDIRS = src auth-dialog auth-dialog-general properties po
else
SUBDIRS = src
endif

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-ppp-starter.conf

nmvpnservice_in_files = nm-ppp-starter.name.in
nmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnservice_DATA = $(nmvpnservice_in_files:.name.in=.name)

%.name: %.name.in Makefile
	@sed -e "s|%bindir%|$(bindir)|g" \
	     -e "s|%libdir%|$(libdir)|g" \
	     -e "s|%libexecdir%|$(libexecdir)|g" $< > $@

if WITH_GNOME
desktopdir = $(datadir)/applications
desktop_in_files = nm-ppp.desktop.in
desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)
@INTLTOOL_DESKTOP_RULE@

icondir = $(datadir)/icons/hicolor/48x48/apps
icon_DATA = gnome-mime-application-x-pptp-settings.png
endif

EXTRA_DIST =\
	$(nmvpnservice_in_files)	\
	$(dbusservice_DATA)		\
	$(desktop_in_files)		\
	$(icon_DATA)			\
	intltool-extract.in		\
	intltool-merge.in		\
	intltool-update.in

CLEANFILES = $(desktop_DATA) $(nmvpnservice_DATA) *~
DISTCLEANFILES = intltool-extract intltool-merge intltool-update
