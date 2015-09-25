include $(GLIB_MAKEFILE)

SUBDIRS = . tests

AM_CPPFLAGS = \
	-I${top_srcdir} \
	-I${top_srcdir}/include \
	-I$(top_builddir)/include \
	-DG_LOG_DOMAIN=\""libnm-util"\" \
	-DLOCALEDIR=\"$(datadir)/locale\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(UUID_CFLAGS)

if WITH_GNUTLS
AM_CPPFLAGS += $(GNUTLS_CFLAGS)
endif

if WITH_NSS
AM_CPPFLAGS += $(NSS_CFLAGS)
endif

lib_LTLIBRARIES=libnm-util.la

libnm_util_include_HEADERS = 		\
	$(top_builddir)/include/nm-version-macros.h \
	NetworkManager.h		\
	NetworkManagerVPN.h		\
	nm-connection.h			\
	nm-setting.h			\
	nm-setting-8021x.h		\
	nm-setting-adsl.h		\
	nm-setting-bluetooth.h		\
	nm-setting-bond.h		\
	nm-setting-team.h		\
	nm-setting-team-port.h		\
	nm-setting-bridge.h		\
	nm-setting-bridge-port.h	\
	nm-setting-connection.h		\
	nm-setting-dcb.h                \
	nm-setting-infiniband.h		\
	nm-setting-ip4-config.h		\
	nm-setting-vlan.h		\
	nm-setting-ip6-config.h		\
	nm-setting-ppp.h		\
	nm-setting-pppoe.h		\
	nm-setting-serial.h		\
	nm-setting-generic.h		\
	nm-setting-gsm.h		\
	nm-setting-cdma.h		\
	nm-setting-olpc-mesh.h		\
	nm-setting-wimax.h		\
	nm-setting-wired.h		\
	nm-setting-wireless.h		\
	nm-setting-wireless-security.h	\
	nm-setting-vpn.h		\
	nm-utils.h \
	nm-version.h

nodist_libnm_util_include_HEADERS = \
	nm-utils-enum-types.h

libnm_util_la_private_headers = \
	crypto.h			\
	nm-dbus-glib-types.h		\
	nm-gvaluearray-compat.h		\
	nm-param-spec-specialized.h	\
	nm-setting-private.h		\
	nm-utils-private.h

libnm_util_la_csources = \
	crypto.c			\
	nm-connection.c			\
	nm-param-spec-specialized.c	\
	nm-setting.c			\
	nm-setting-8021x.c		\
	nm-setting-adsl.c		\
	nm-setting-bluetooth.c		\
	nm-setting-bond.c		\
	nm-setting-team.c		\
	nm-setting-team-port.c		\
	nm-setting-bridge.c		\
	nm-setting-bridge-port.c	\
	nm-setting-connection.c		\
	nm-setting-dcb.c                \
	nm-setting-infiniband.c		\
	nm-setting-ip4-config.c		\
	nm-setting-vlan.c		\
	nm-setting-ip6-config.c		\
	nm-setting-ppp.c		\
	nm-setting-pppoe.c		\
	nm-setting-serial.c		\
	nm-setting-generic.c		\
	nm-setting-gsm.c		\
	nm-setting-cdma.c		\
	nm-setting-olpc-mesh.c		\
	nm-setting-wimax.c		\
	nm-setting-wired.c		\
	nm-setting-wireless.c		\
	nm-setting-wireless-security.c	\
	nm-setting-vpn.c		\
	nm-utils-enum-types.c		\
	nm-utils.c			\
	nm-value-transforms.c

libnm_util_la_SOURCES = \
	$(libnm_util_la_csources) \
	$(libnm_util_la_private_headers)

GLIB_GENERATED = nm-utils-enum-types.h nm-utils-enum-types.c
BUILT_SOURCES = $(GLIB_GENERATED)
nm_utils_enum_types_sources = $(filter-out NetworkManager%,$(libnm_util_include_HEADERS))
GLIB_MKENUMS_H_FLAGS = --identifier-prefix NM
GLIB_MKENUMS_C_FLAGS = --identifier-prefix NM

libnm_util_la_LIBADD = $(GLIB_LIBS) $(DBUS_LIBS) $(UUID_LIBS)

SYMBOL_VIS_FILE=$(srcdir)/libnm-util.ver

libnm_util_la_LDFLAGS = -Wl,--version-script=$(SYMBOL_VIS_FILE) \
	-version-info "9:0:7"

if WITH_GNUTLS
libnm_util_la_SOURCES += crypto_gnutls.c
libnm_util_la_LIBADD += $(GNUTLS_LIBS)
endif

if WITH_NSS
libnm_util_la_SOURCES += crypto_nss.c
libnm_util_la_LIBADD += $(NSS_LIBS)
endif

libnm_util_includedir=$(includedir)/NetworkManager


###########################################
# Crypto test library
###########################################

noinst_LTLIBRARIES = libtest-crypto.la

libtest_crypto_la_SOURCES = crypto.c

libtest_crypto_la_LIBADD = \
	$(GLIB_LIBS)

if WITH_GNUTLS
libtest_crypto_la_SOURCES += crypto_gnutls.c
libtest_crypto_la_LIBADD += $(GNUTLS_LIBS)
endif

if WITH_NSS
libtest_crypto_la_SOURCES += crypto_nss.c
libtest_crypto_la_LIBADD += $(NSS_LIBS)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnm-util.pc

DISTCLEANFILES = libnm-util.pc

EXTRA_DIST = libnm-util.pc.in libnm-util.ver

-include $(INTROSPECTION_MAKEFILE)
INTROSPECTION_GIRS =
INTROSPECTION_SCANNER_ARGS = --add-include-path=$(srcdir)
INTROSPECTION_COMPILER_ARGS = --includedir=$(srcdir)

if HAVE_INTROSPECTION
introspection_sources = $(libnm_util_include_HEADERS) $(nodist_libnm_util_include_HEADERS) $(libnm_util_la_csources)

NetworkManager-1.0.gir: libnm-util.la
NetworkManager_1_0_gir_INCLUDES = GObject-2.0 DBusGLib-1.0
NetworkManager_1_0_gir_PACKAGES = gobject-2.0 dbus-glib-1
NetworkManager_1_0_gir_EXPORT_PACKAGES = libnm-util
NetworkManager_1_0_gir_CFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/libnm-util
NetworkManager_1_0_gir_LIBS = libnm-util.la
NetworkManager_1_0_gir_FILES = $(introspection_sources)
NetworkManager_1_0_gir_SCANNERFLAGS = --warn-all --identifier-prefix=NM --symbol-prefix=nm
INTROSPECTION_GIRS += NetworkManager-1.0.gir

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

CLEANFILES = $(gir_DATA) $(typelib_DATA)

endif

if ENABLE_TESTS

check-local:
	$(top_srcdir)/tools/check-exports.sh $(builddir)/.libs/libnm-util.so $(SYMBOL_VIS_FILE)

endif

