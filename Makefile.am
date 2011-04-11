SUBDIRS = \
	marshallers \
	include \
	libnm-util \
	libnm-glib \
	introspection \
	src \
	callouts \
	cli \
	tools \
	policy \
	data \
	initscript \
	test \
	po \
	man \
	docs \
	examples

EXTRA_DIST = \
	CONTRIBUTING \
	NetworkManager.pc.in \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in		

DISTCHECK_CONFIGURE_FLAGS = \
	--with-tests=yes \
	--with-docs=yes \
	--enable-more-warnings=yes \
	--with-udev-dir=$$dc_install_base/lib/udev \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

DISTCLEANFILES = intltool-extract intltool-merge intltool-update

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = NetworkManager.pc

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

