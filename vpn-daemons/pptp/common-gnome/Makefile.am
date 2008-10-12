noinst_LTLIBRARIES=libnm-pptp-common-gnome.la

libnm_pptp_common_gnome_la_CPPFLAGS = \
	$(NM_UTILS_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GNOMEKEYRING_CFLAGS) \
	-DG_DISABLE_DEPRECATED

libnm_pptp_common_gnome_la_SOURCES= \
	keyring-helpers.c \
	keyring-helpers.h

libnm_pptp_common_gnome_la_LIBADD = \
	$(NM_UTILS_LIBS) \
	$(GLIB_LIBS) \
	$(GNOMEKEYRING_LIBS)

