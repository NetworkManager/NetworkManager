man_MANS =
CLEANFILES =

if ENABLE_DOC

XSLTPROC = xsltproc --xinclude --nonet

nm-settings.5: nm-settings.xml
	$(XSLTPROC) $(top_srcdir)/tools/manpages-docbook.xsl $(builddir)/nm-settings.xml
CLEANFILES += nm-settings.5

nm-settings.xml: $(top_builddir)/tools/generate-settings-spec $(top_builddir)/libnm-util/libnm-util.la
	rm -f $(builddir)/$@
	$(top_builddir)/tools/generate-settings-spec refentry $(builddir)/$@
CLEANFILES += nm-settings.xml

XSLTPROC_FLAGS = \
        --nonet \
        --stringparam man.output.quietly 1 \
        --stringparam funcsynopsis.style ansi \
        --stringparam man.th.extra1.suppress 1 \
        --stringparam man.authors.section.enabled 0 \
        --stringparam man.copyright.section.enabled 0

XSLTPROC_MAN_FLAGS = $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl

%.8: %.xml
	$(AM_V_GEN) xsltproc $(XSLTPROC_MAN_FLAGS) $<

%.5: %.xml
	$(AM_V_GEN) xsltproc $(XSLTPROC_MAN_FLAGS) $<

man_MANS +=				\
	NetworkManager.8		\
	NetworkManager.conf.5		\
	nm-system-settings.conf.5	\
	nm-online.1			\
	nmcli.1				\
	nm-settings.5

endif
