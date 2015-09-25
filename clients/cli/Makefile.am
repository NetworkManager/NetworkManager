bin_PROGRAMS = \
	nmcli

AM_CPPFLAGS = \
	-I${top_srcdir} \
	-I${top_builddir} \
	-I${top_srcdir}/include \
	-I$(top_builddir)/include \
	-I${top_srcdir}/libnm-core \
	-I${top_builddir}/libnm-core \
	-I${top_srcdir}/libnm \
	-I${top_builddir}/libnm \
	-I${top_srcdir}/clients/common \
	$(GLIB_CFLAGS) \
	-DG_LOG_DOMAIN=\""nmcli"\" \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DNMCLI_LOCALEDIR=\"$(datadir)/locale\"

nmcli_SOURCES = \
	agent.c \
	agent.h \
	common.c \
	common.h \
	connections.c \
	connections.h \
	devices.c \
	devices.h \
	general.c \
	general.h \
	settings.c \
	settings.h \
	nmcli.c \
	nmcli.h \
	utils.c \
	utils.h \
	polkit-agent.c \
	polkit-agent.h \
	\
	$(srcdir)/../common/nm-secret-agent-simple.c \
	$(srcdir)/../common/nm-secret-agent-simple.h \
	$(NULL)

nmcli_LDADD = \
	$(GLIB_LIBS) \
	$(READLINE_LIBS) \
	$(top_builddir)/libnm/libnm.la

if WITH_POLKIT_AGENT
AM_CPPFLAGS += $(POLKIT_CFLAGS)
nmcli_SOURCES += $(srcdir)/../common/nm-polkit-listener.c $(srcdir)/../common/nm-polkit-listener.h
nmcli_LDADD += $(POLKIT_LIBS)
endif

if BUILD_SETTING_DOCS
settings-docs.c: settings-docs.xsl $(top_builddir)/libnm/nm-property-docs.xml
	$(AM_V_GEN) xsltproc --output $@ $^

BUILT_SOURCES = settings-docs.c
CLEANFILES = settings-docs.c
endif

EXTRA_DIST = settings-docs.c settings-docs.xsl

completiondir = $(datadir)/bash-completion/completions

install-data-hook:
	$(mkinstalldirs) $(DESTDIR)$(completiondir)
	$(INSTALL_DATA) $(srcdir)/nmcli-completion $(DESTDIR)$(completiondir)/nmcli

uninstall-hook:
	rm -f $(DESTDIR)$(completiondir)/nmcli

EXTRA_DIST += nmcli-completion
