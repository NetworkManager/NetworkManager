include $(GLIB_MAKEFILE)

@GNOME_CODE_COVERAGE_RULES@

SUBDIRS = . tests

AM_CPPFLAGS = \
	-I${top_srcdir}/shared \
	-I${top_builddir}/shared \
	-DG_LOG_DOMAIN=\""libnm"\" \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-DNMCONFDIR=\"$(nmconfdir)\" \
	-DNMLIBDIR=\"$(nmlibdir)\" \
	-DNMPLUGINDIR=\"$(pkglibdir)\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
	$(GLIB_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS)

noinst_LTLIBRARIES = libnm-core.la

# header/source defines are in Makefile.libnm-core, so they can be shared
# with libnm/Makefile.am
include Makefile.libnm-core

libnmincludedir = $(includedir)/libnm

libnminclude_HEADERS = $(libnm_core_headers)
libnm_core_la_SOURCES =			\
	$(libnm_core_sources)		\
	$(libnm_core_private_headers)

GLIB_GENERATED = nm-core-enum-types.h nm-core-enum-types.c
nm_core_enum_types_sources = $(filter-out %nm-core-enum-types.h,$(libnminclude_HEADERS))
GLIB_MKENUMS_H_FLAGS = --identifier-prefix NM
GLIB_MKENUMS_C_FLAGS = --identifier-prefix NM

libnm_core_la_LIBADD =			\
	$(GLIB_LIBS)			\
	$(UUID_LIBS)

libnm_core_la_LDFLAGS =			\
	$(CODE_COVERAGE_LDFLAGS)

if WITH_GNUTLS
AM_CPPFLAGS += $(GNUTLS_CFLAGS)
libnm_core_la_SOURCES += crypto_gnutls.c
libnm_core_la_LIBADD += $(GNUTLS_LIBS)
endif

if WITH_NSS
AM_CPPFLAGS += $(NSS_CFLAGS)
libnm_core_la_SOURCES += crypto_nss.c
libnm_core_la_LIBADD += $(NSS_LIBS)
endif

nm-vpn-dbus-types.xml: nm-vpn-dbus-interface.h $(top_srcdir)/tools/enums-to-docbook.pl
	$(AM_V_GEN) @PERL@ $(top_srcdir)/tools/enums-to-docbook.pl 'nm-vpn-dbus-types' 'VPN Plugin D-Bus API Types' $^ >$@

nm-dbus-types.xml: nm-dbus-interface.h $(top_srcdir)/tools/enums-to-docbook.pl
	$(AM_V_GEN) @PERL@ $(top_srcdir)/tools/enums-to-docbook.pl 'nm-dbus-types' 'NetworkManager D-Bus API Types' $^ >$@

BUILT_SOURCES = $(GLIB_GENERATED) nm-vpn-dbus-types.xml nm-dbus-types.xml
CLEANFILES = $(BUILT_SOURCES)
