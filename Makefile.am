include $(GLIB_MAKEFILE)

SUBDIRS = \
	. \
	include \
	introspection \
	libnm-core \
	libnm \
	libnm-util \
	libnm-glib \
	src \
	callouts \
	clients \
	tools \
	policy \
	data \
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
	--enable-more-warnings=error \
	--with-udev-dir=$$dc_install_base/lib/udev \
	--with-wext=no \
	--enable-ifcfg-rh \
	--enable-ifupdown \
	--enable-ifnet

if BUILD_SETTING_DOCS
dist-check-setting-docs:
else
dist-check-setting-docs:
	@echo "*** gobject-introspection and pygobject are needed to run 'make dist'. ***"
	@false
endif

dist: dist-check-setting-docs

DISTCLEANFILES = intltool-extract intltool-merge intltool-update

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = NetworkManager.pc

CLEANFILES = cscope.in.out cscope.out cscope.po.out

cscope:
	cscope -b -q -R -Iinclude -ssrc -slibnm-core -slibnm -slibnm-glib -slibnm-util -sclients;

.PHONY: cscope
