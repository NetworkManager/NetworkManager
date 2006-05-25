INCLUDES = -I${top_srcdir} -I${top_srcdir}/include

lib_LTLIBRARIES=libnm-util.la

libnm_util_la_CPPFLAGS =				\
	$(GLIB_CFLAGS)					\
	$(DBUS_CFLAGS)					\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DG_DISABLE_DEPRECATED			\
	-DGDK_DISABLE_DEPRECATED			\
	-DGNOME_DISABLE_DEPRECATED		\
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"

if WITH_GCRYPT
libnm_util_la_CPPFLAGS += $(LIBGCRYPT_CFLAGS)
endif

libnm_util_la_SOURCES=			\
	cipher.c					\
	cipher.h					\
	cipher-private.h			\
	cipher-wep-hex.c			\
	cipher-wep-hex.h			\
	cipher-wep-passphrase.c		\
	cipher-wep-passphrase.h		\
	cipher-wep-ascii.c			\
	cipher-wep-ascii.h			\
	cipher-wpa-psk-hex.c		\
	cipher-wpa-psk-hex.h		\
	cipher-wpa-psk-passphrase.c	\
	cipher-wpa-psk-passphrase.h	\
	dbus-helpers.c				\
	dbus-helpers.h				\
	sha1.c					\
	sha1.h					\
	dbus-method-dispatcher.c		\
	dbus-method-dispatcher.h

if !WITH_GCRYPT
libnm_util_la_SOURCES += gnome-keyring-md5.c gnome-keyring-md5.h
endif

libnm_util_la_LDFLAGS= $(GLIB_LIBS) $(DBUS_LIBS)

if WITH_GCRYPT
libnm_util_la_LDFLAGS += $(LIBGCRYPT_LIBS)
endif

libnm_util_includedir=$(includedir)/NetworkManager

libnm_util_include_HEADERS = 		\
	cipher.h					\
	cipher-wep-hex.h			\
	cipher-wep-passphrase.h		\
	cipher-wep-ascii.h			\
	cipher-wpa-psk-hex.h		\
	cipher-wpa-psk-passphrase.h	\
	dbus-helpers.h				\
	dbus-method-dispatcher.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnm-util.pc

DISTCLEANFILES = libnm-util.pc

EXTRA_DIST = libnm-util.pc.in
