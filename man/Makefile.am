
if ENABLE_DOC

XSLTPROC = xsltproc --xinclude --nonet

GENERATED_FILES = nm-settings.xml nm-settings.5

nm-settings.5: nm-settings.xml
	$(XSLTPROC) $(top_srcdir)/tools/manpages-docbook.xsl $(builddir)/nm-settings.xml

nm-settings.xml: $(top_builddir)/tools/generate-settings-spec $(top_builddir)/libnm-util/libnm-util.la
	rm -f $(builddir)/$@
	$(top_builddir)/tools/generate-settings-spec refentry $(builddir)/$@

else

GENERATED_FILES =

endif

man_MANS =				\
	NetworkManager.8		\
	NetworkManager.conf.5		\
	nm-system-settings.conf.5	\
	nm-tool.1			\
	nm-online.1			\
	nmcli.1				\
	$(GENERATED_FILES)

EXTRA_DIST =				\
	$(man_MANS)			\
	NetworkManager.8.in		\
	NetworkManager.conf.5.in	\
	nm-system-settings.conf.5.in	\
	nm-tool.1.in			\
	nm-online.1.in			\
	nmcli.1.in

CLEANFILES = $(man_MANS) $(GENERATED_FILES)

