SUBDIRS = libnm-glib libnm-util

if WITH_DOCS

XSLTPROC = xsltproc --xinclude --nonet
XMLS = $(wildcard $(top_srcdir)/introspection/nm-*.xml)

OTHER_FILES= \
	$(top_srcdir)/introspection/all.xml \
	$(top_srcdir)/introspection/generic-types.xml \
	$(top_srcdir)/introspection/errors.xml \
	$(top_srcdir)/introspection/vpn-errors.xml \
	$(top_srcdir)/tools/doc-generator.xsl \
	$(top_srcdir)/introspection/generic-types.xml

GENERATED_FILES = spec.html

spec.html: $(XMLS) $(OTHER_FILES)
	@install -d docs
	$(XSLTPROC) $(top_srcdir)/tools/doc-generator.xsl $(top_srcdir)/introspection/all.xml > $@

EXTRA_DIST = $(GENERATED_FILES)

CLEANFILES = $(GENERATED_FILES)

endif

