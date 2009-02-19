SUBDIRS = marshallers

if NO_GIO
SUBDIRS += gfilemonitor
endif

SUBDIRS += \
	   libnm-util \
	   libnm-glib \
	   src \
	   include \
	   introspection \
	   callouts \
	   system-settings \
	   tools \
	   policy \
	   initscript \
	   test \
	   po \
	   man \
	   docs

EXTRA_DIST = \
	CONTRIBUTING \
	NetworkManager.pc.in \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in		

DISTCHECK_CONFIGURE_FLAGS = --with-tests=yes --with-docs=yes --with-udev-dir=$$dc_install_base/lib/udev

DISTCLEANFILES = intltool-extract intltool-merge intltool-update

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = NetworkManager.pc

