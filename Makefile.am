SUBDIRS = 				\
	   utils				\
	   libnm-util			\
	   src				\
	   dispatcher-daemon	\
	   gnome				\
	   initscript			\
	   test				\
	   po				\
	   man				\
	   include

EXTRA_DIST =				\
	CONTRIBUTING			\
	NetworkManager.pc.in	\
	intltool-extract.in		\
	intltool-merge.in		\
	intltool-update.in		
	
if WITH_GNOME
EXTRA_DIST +=				\
	nm-applet.desktop
endif

DISTCLEANFILES = intltool-extract intltool-merge intltool-update

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = NetworkManager.pc

if WITH_GNOME
autostartdir = $(datadir)/gnome/autostart
autostart_DATA = nm-applet.desktop
endif
