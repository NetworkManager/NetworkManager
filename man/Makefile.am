man_MANS =
CLEANFILES =

if ENABLE_GTK_DOC

XSLTPROC = xsltproc --xinclude --nonet

nm-settings.5: nm-settings.xml
	$(XSLTPROC) $(top_srcdir)/tools/manpages-docbook.xsl $(builddir)/nm-settings.xml

nm-settings.xml: $(top_builddir)/tools/generate-settings-spec $(top_builddir)/libnm-util/libnm-util.la
	rm -f $(builddir)/$@
	$(top_builddir)/tools/generate-settings-spec refentry $(builddir)/$@

endif

CLEANFILES += nm-settings.5 nm-settings.xml

man_MANS +=				\
	NetworkManager.8		\
	NetworkManager.conf.5		\
	nm-system-settings.conf.5	\
	nm-tool.1			\
	nm-online.1			\
	nmcli.1

if ENABLE_GTK_DOC
man_MANS += nm-settings.5
else
if INSTALL_PREGEN_MANPAGES
man_MANS += nm-settings.5
endif
endif

