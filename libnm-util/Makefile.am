SUBDIRS=. tests

INCLUDES = -I${top_srcdir} -I${top_srcdir}/include

lib_LTLIBRARIES=libnm-util.la

libnm_util_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(UUID_CFLAGS) \
	-DG_DISABLE_DEPRECATED

libnm_util_include_HEADERS = 		\
	nm-connection.h			\
	nm-setting.h			\
	nm-setting-8021x.h		\
	nm-setting-bluetooth.h		\
	nm-setting-connection.h		\
	nm-setting-ip4-config.h		\
	nm-setting-ip6-config.h		\
	nm-setting-ppp.h		\
	nm-setting-pppoe.h		\
	nm-setting-serial.h		\
	nm-setting-gsm.h		\
	nm-setting-cdma.h		\
	nm-setting-olpc-mesh.h		\
	nm-setting-wimax.h		\
	nm-setting-wired.h		\
	nm-setting-wireless.h		\
	nm-setting-wireless-security.h	\
	nm-setting-vpn.h		\
	nm-utils.h

libnm_util_la_private_headers = \
	crypto.h			\
	nm-param-spec-specialized.h	\
	nm-utils-private.h \
	nm-setting-private.h

libnm_util_la_csources = \
	crypto.c			\
	nm-connection.c			\
	nm-param-spec-specialized.c	\
	nm-setting.c			\
	nm-setting-8021x.c		\
	nm-setting-bluetooth.c		\
	nm-setting-connection.c		\
	nm-setting-ip4-config.c		\
	nm-setting-ip6-config.c		\
	nm-setting-ppp.c		\
	nm-setting-pppoe.c		\
	nm-setting-serial.c		\
	nm-setting-gsm.c		\
	nm-setting-cdma.c		\
	nm-setting-olpc-mesh.c		\
	nm-setting-wimax.c		\
	nm-setting-wired.c		\
	nm-setting-wireless.c		\
	nm-setting-wireless-security.c	\
	nm-setting-vpn.c		\
	nm-utils.c

libnm_util_la_SOURCES = \
	$(libnm_util_la_csources) \
	$(libnm_util_la_private_headers)

libnm_util_la_LIBADD = $(GLIB_LIBS) $(DBUS_LIBS) $(UUID_LIBS)

SYMBOL_VIS_FILE=$(srcdir)/libnm-util.ver

libnm_util_la_LDFLAGS = -Wl,--version-script=$(SYMBOL_VIS_FILE) \
	-version-info "2:0:0"

if WITH_GNUTLS
libnm_util_la_SOURCES += crypto_gnutls.c
libnm_util_la_CPPFLAGS += $(LIBGCRYPT_CFLAGS) $(GNUTLS_CFLAGS)
libnm_util_la_LIBADD += $(LIBGCRYPT_LIBS) $(GNUTLS_LIBS)
endif

if WITH_NSS
libnm_util_la_SOURCES += crypto_nss.c
libnm_util_la_CPPFLAGS += $(NSS_CFLAGS)
libnm_util_la_LIBADD += $(NSS_LIBS)
endif

libnm_util_includedir=$(includedir)/NetworkManager


###########################################
# Crypto test library
###########################################

noinst_LTLIBRARIES = libtest-crypto.la

libtest_crypto_la_SOURCES = crypto.c

libtest_crypto_la_CPPFLAGS = \
	$(GLIB_CFLAGS)

libtest_crypto_la_LIBADD = \
	$(GLIB_LIBS)

if WITH_GNUTLS
libtest_crypto_la_SOURCES += crypto_gnutls.c
libtest_crypto_la_CPPFLAGS += $(LIBGCRYPT_CFLAGS) $(GNUTLS_CFLAGS)
libtest_crypto_la_LIBADD += $(LIBGCRYPT_LIBS) $(GNUTLS_LIBS)
endif

if WITH_NSS
libtest_crypto_la_SOURCES += crypto_nss.c
libtest_crypto_la_CPPFLAGS += $(NSS_CFLAGS)
libtest_crypto_la_LIBADD += $(NSS_LIBS)
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnm-util.pc

DISTCLEANFILES = libnm-util.pc
CLEANFILES = 

EXTRA_DIST = libnm-util.pc.in libnm-util.ver

-include $(INTROSPECTION_MAKEFILE)
INTROSPECTION_GIRS =
INTROSPECTION_SCANNER_ARGS = --add-include-path=$(srcdir)
INTROSPECTION_COMPILER_ARGS = --includedir=$(srcdir)

if HAVE_INTROSPECTION
introspection_sources = $(libnm_util_include_HEADERS) $(libnm_util_la_csources) $(top_srcdir)/include/NetworkManager.h $(top_srcdir)/include/NetworkManagerVPN.h

NetworkManager-1.0.gir: libnm-util.la
NetworkManager_1_0_gir_INCLUDES = GObject-2.0 DBusGLib-1.0
NetworkManager_1_0_gir_PACKAGES = gobject-2.0 dbus-glib-1
NetworkManager_1_0_gir_CFLAGS = $(INCLUDES) -I$(top_srcdir)/libnm-util
NetworkManager_1_0_gir_LIBS = libnm-util.la
NetworkManager_1_0_gir_FILES = $(introspection_sources)
NetworkManager_1_0_gir_SCANNERFLAGS = --warn-all --identifier-prefix=NM --symbol-prefix=nm_
INTROSPECTION_GIRS += NetworkManager-1.0.gir

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

CLEANFILES += $(gir_DATA) $(typelib_DATA)
endif

if WITH_TESTS

check-local:
	$(top_srcdir)/tools/check-exports.sh $(builddir)/.libs/libnm-util.so $(SYMBOL_VIS_FILE)

endif

