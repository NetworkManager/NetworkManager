INCLUDES = -I${top_srcdir}/utils \
           -I${top_srcdir}/src \
           -I${top_srcdir}/include \
           -I${top_srcdir}/libnm-util \
           -I${top_srcdir}/src/named-manager

noinst_LTLIBRARIES = libsupplicant-manager.la

BUILT_SOURCES = \
	nm-supplicant-marshal.h \
	nm-supplicant-marshal.c

libsupplicant_manager_la_SOURCES = \
	nm-supplicant-types.h \
	nm-supplicant-manager.h \
	nm-supplicant-manager.c \
	nm-supplicant-config.h \
	nm-supplicant-config.c \
	nm-supplicant-interface.c \
	nm-supplicant-interface.h \
	nm-supplicant-settings-verify.h \
	nm-supplicant-settings-verify.c \
	nm-supplicant-marshal-main.c

libsupplicant_manager_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(GTHREAD_CFLAGS) \
	$(HAL_CFLAGS) \
	-DNM_PKGDATADIR=\"$(pkgdatadir)\" \
	-DNM_LOCALSTATEDIR=\"$(localstatedir)\" \
	-DDBUS_API_SUBJECT_TO_CHANGE

libsupplicant_manager_la_LIBADD = \
	$(DBUS_LIBS) \
	$(GTHREAD_LIBS)

$(libsupplicant_manager_la_OBJECTS): $(BUILT_SOURCES)

EXTRA_DIST = \
	nm-supplicant-marshal.list

CLEANFILES = $(BUILT_SOURCES)

nm-supplicant-marshal.h: nm-supplicant-marshal.list
	$(GLIB_GENMARSHAL) --prefix=nm_supplicant_marshal $(srcdir)/nm-supplicant-marshal.list --header > \
		xgen-gmh \
	&& (cmp -s xgen-gmh nm-supplicant-marshal.h || cp xgen-gmh nm-supplicant-marshal.h) \
	&& rm -f xgen-gmh xgen-gmh~

nm-supplicant-marshal.c: nm-supplicant-marshal.list
	$(GLIB_GENMARSHAL) --prefix=nm_supplicant_marshal $(srcdir)/nm-supplicant-marshal.list --body > \
		xgen-gmc \
	&& cp xgen-gmc nm-supplicant-marshal.c \
	&& rm -f xgen-gmc xgen-gmc~

nm-supplicant-marshal-main.c: nm-supplicant-marshal.c nm-supplicant-marshal.h
