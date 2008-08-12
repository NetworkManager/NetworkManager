if WITH_DOCS

all:

XSLTPROC = xsltproc --xinclude --nonet

XMLS = $(wildcard introspection/nm-*.xml)
# Figure out if we need ASYNC_INTROSPECT and add it later

GENERATED_FILES = \
	docs/spec.html

docs/spec.html: $(XMLS) introspection/all.xml introspection/generic-types.xml introspection/errors.xml introspection/vpn-errors.xml tools/doc-generator.xsl introspection/generic-types.xml
	@install -d docs
	$(XSLTPROC) tools/doc-generator.xsl introspection/all.xml > $@

all: $(GENERATED_FILES)

clean:
	rm -f $(GENERATED_FILES)

endif

SUBDIRS = marshallers

if NO_GIO
SUBDIRS += gfilemonitor
endif

SUBDIRS += \
	   libnm-util			\
	   libnm-glib			\
	   src				\
	   initscript			\
	   test				\
	   po				\
	   man				\
	   include			\
	   introspection	\
	   callouts \
	   system-settings \
	   tools \
	   policy \
	   docs/libnm-glib

EXTRA_DIST =				\
	CONTRIBUTING			\
	NetworkManager.pc.in	\
	intltool-extract.in		\
	intltool-merge.in		\
	intltool-update.in		

DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc

DISTCLEANFILES = intltool-extract intltool-merge intltool-update

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = NetworkManager.pc
