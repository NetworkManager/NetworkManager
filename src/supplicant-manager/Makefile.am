INCLUDES = \
	-I${top_srcdir}/src \
	-I${top_srcdir}/include \
	-I${top_srcdir}/libnm-util \
	-I${top_builddir}/marshallers \
	-I${top_srcdir}/src/named-manager

noinst_LTLIBRARIES = libsupplicant-manager.la

libsupplicant_manager_la_SOURCES = \
	nm-supplicant-types.h \
	nm-supplicant-manager.h \
	nm-supplicant-manager.c \
	nm-supplicant-config.h \
	nm-supplicant-config.c \
	nm-supplicant-interface.c \
	nm-supplicant-interface.h \
	nm-supplicant-settings-verify.h \
	nm-supplicant-settings-verify.c

libsupplicant_manager_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(HAL_CFLAGS) \
	-DNM_PKGDATADIR=\"$(pkgdatadir)\" \
	-DNM_LOCALSTATEDIR=\"$(localstatedir)\"

libsupplicant_manager_la_LIBADD = \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(top_builddir)/marshallers/libmarshallers.la

