include $(GLIB_MAKEFILE)

SUBDIRS = \
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
	test \
	po \
	man \
	docs \
	examples \
	vapi

EXTRA_DIST = \
	CONTRIBUTING \
	NetworkManager.pc.in \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in \
	Makefile.glib

DISTCHECK_CONFIGURE_FLAGS = \
	--with-tests=yes \
	--with-docs=yes \
	--enable-more-warnings=yes \
	--with-udev-dir=$$dc_install_base/lib/udev \
	--with-wext=no \
	--enable-ifcfg-rh \
	--enable-ifcfg-suse \
	--enable-ifupdown \
	--enable-ifnet

DISTCLEANFILES = intltool-extract intltool-merge intltool-update

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = NetworkManager.pc

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

CLEANFILES = cscope.in.out cscope.out cscope.po.out

.PHONY: cscope
cscope:
	cscope -b -q -R -Iinclude -ssrc -slibnm-glib -slibnm-util -scli/src;
