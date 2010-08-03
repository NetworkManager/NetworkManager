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
	nm-setting-wired.h		\
	nm-setting-wireless.h		\
	nm-setting-wireless-security.h	\
	nm-setting-vpn.h		\
	nm-utils.h

libnm_util_la_SOURCES=			\
	crypto.c			\
	crypto.h			\
	nm-connection.c			\
	nm-param-spec-specialized.c	\
	nm-param-spec-specialized.h \
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
	nm-setting-wired.c		\
	nm-setting-wireless.c		\
	nm-setting-wireless-security.c	\
	nm-setting-vpn.c		\
	nm-utils.c			\
	nm-utils-private.h \
	$(libnm_util_include_HEADERS)

libnm_util_la_LIBADD = $(GLIB_LIBS) $(DBUS_LIBS) $(UUID_LIBS)

libnm_util_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libnm-util.ver \
	-version-info "7:0:6"

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

EXTRA_DIST = libnm-util.pc.in libnm-util.ver

