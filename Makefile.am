include $(GLIB_MAKEFILE)

SUBDIRS = \
	. \
	include \
	libnm-util \
	libnm-glib \
	introspection \
	src \
	callouts \
	cli \
	tui \
	tools \
	policy \
	data \
	test \
	po \
	docs \
	man \
	examples \
	vapi

@GNOME_CODE_COVERAGE_RULES@

EXTRA_DIST = \
	CONTRIBUTING \
	NetworkManager.pc.in \
	intltool-extract.in \
	intltool-merge.in \
	intltool-update.in \
	Makefile.glib \
	autogen.sh \
	valgrind.suppressions

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-tests=yes \
	--with-valgrind=no \
	--enable-gtk-doc \
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

cscope:
	cscope -b -q -R -Iinclude -ssrc -slibnm-glib -slibnm-util -scli/src;

libgsystem_srcpath := libgsystem
libgsystem_cflags := $(filter-out -DGLIB_VERSION%,$(GLIB_CFLAGS)) -I$(srcdir)/libgsystem
libgsystem_libs = $(GLIB_LIBS)
include libgsystem/Makefile-libgsystem.am
noinst_LTLIBRARIES = libgsystem.la

.PHONY: cscope
