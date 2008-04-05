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
	$(GTHREAD_CFLAGS) \
	$(HAL_CFLAGS) \
	-DNM_PKGDATADIR=\"$(pkgdatadir)\" \
	-DNM_LOCALSTATEDIR=\"$(localstatedir)\" \
	-DDBUS_API_SUBJECT_TO_CHANGE

libsupplicant_manager_la_LIBADD = \
	$(DBUS_LIBS) \
	$(GTHREAD_LIBS) \
	$(top_builddir)/marshallers/libmarshallers.la

$(libsupplicant_manager_la_OBJECTS): $(BUILT_SOURCES)

CLEANFILES = $(BUILT_SOURCES)

