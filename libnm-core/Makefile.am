include $(GLIB_MAKEFILE)

SUBDIRS = . tests

AM_CPPFLAGS = \
	-I${top_srcdir}/include \
	-DG_LOG_DOMAIN=\""libnm"\" \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-DNMCONFDIR=\"$(nmconfdir)\" \
	-DNMLIBDIR=\"$(nmlibdir)\" \
	-DNETWORKMANAGER_COMPILATION \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS)

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
nm_core_enum_types_sources = $(notdir $(libnminclude_HEADERS))
GLIB_MKENUMS_H_FLAGS = --identifier-prefix NM
GLIB_MKENUMS_C_FLAGS = --identifier-prefix NM

libnm_core_la_LIBADD =			\
	$(GLIB_LIBS)			\
	$(UUID_LIBS)

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

BUILT_SOURCES = $(GLIB_GENERATED)
CLEANFILES = $(BUILT_SOURCES)
