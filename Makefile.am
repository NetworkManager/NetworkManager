SUBDIRS = utils src dispatcher-daemon gnome initscript test po

EXTRA_DIST =				\
	CONTRIBUTING			\
	NetworkManager.pc.in		\
	NetworkManager.h		\
	intltool-extract.in		\
	intltool-merge.in		\
	intltool-update.in

DISTCLEANFILES = intltool-extract intltool-merge intltool-update

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = NetworkManager.pc

NetworkManagerincludedir=$(includedir)/NetworkManager

NetworkManagerinclude_HEADERS = NetworkManager.h
