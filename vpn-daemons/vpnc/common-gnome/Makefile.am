noinst_LTLIBRARIES=libnm-vpnc-common-gnome.la

libnm_vpnc_common_gnome_la_CPPFLAGS = \
	$(NM_UTILS_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GNOMEKEYRING_CFLAGS) \
	-DG_DISABLE_DEPRECATED

libnm_vpnc_common_gnome_la_SOURCES= \
	keyring-helpers.c \
	keyring-helpers.h

libnm_vpnc_common_gnome_la_LIBADD = \
	$(NM_UTILS_LIBS) \
	$(GLIB_LIBS) \
	$(GNOMEKEYRING_LIBS)

