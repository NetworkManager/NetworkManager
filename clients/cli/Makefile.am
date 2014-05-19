bin_PROGRAMS = \
	nmcli

AM_CPPFLAGS = \
	-I${top_srcdir} \
	-I${top_builddir} \
	-I${top_srcdir}/include \
	-I${top_srcdir}/libnm-core \
	-I${top_builddir}/libnm-core \
	-I${top_srcdir}/libnm \
	-I${top_builddir}/libnm \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	-DG_LOG_DOMAIN=\""nmcli"\" \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DNMCLI_LOCALEDIR=\"$(datadir)/locale\"

nmcli_SOURCES = \
	common.c \
	common.h \
	connections.c \
	connections.h \
	devices.c \
	devices.h \
	network-manager.c \
	network-manager.h \
	settings.c \
	settings.h \
	nmcli.c \
	nmcli.h \
	utils.c \
	utils.h

nmcli_LDADD = \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(READLINE_LIBS) \
	$(top_builddir)/libnm/libnm.la

if BUILD_SETTING_DOCS
settings-docs.c: settings-docs.xsl $(top_builddir)/libnm-util/nm-setting-docs.xml
	$(AM_V_GEN) xsltproc --output $@ $^

BUILT_SOURCES = settings-docs.c
endif

DISTCLEANFILES = settings-docs.c

EXTRA_DIST = settings-docs.c settings-docs.xsl

completiondir = $(datadir)/bash-completion/completions

install-data-hook:
	$(mkinstalldirs) $(DESTDIR)$(completiondir)
	$(INSTALL_DATA) $(srcdir)/nmcli-completion $(DESTDIR)$(completiondir)/nmcli

uninstall-hook:
	rm -f $(DESTDIR)$(completiondir)/nmcli

EXTRA_DIST += nmcli-completion
