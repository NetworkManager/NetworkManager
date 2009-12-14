INCLUDES = \
	-I${top_srcdir}/src \
	-I${top_srcdir}/include \
	-I${top_srcdir}/libnm-util \
	-I${top_builddir}/marshallers

noinst_LTLIBRARIES = libwimax.la

libwimax_la_SOURCES = \
	nm-wimax-device.c \
	nm-wimax-device.h \
	nm-wimax-manager.c \
	nm-wimax-manager.h \
	nm-wimax-nsp.c \
	nm-wimax-nsp.h \
	nm-wimax-types.h \
	nm-wimax-util.c \
	nm-wimax-util.h

libwimax_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(WIMAX_CFLAGS)

libwimax_la_LIBADD = \
	$(DBUS_LIBS) \
	$(WIMAX_LIBS) \
	$(top_builddir)/marshallers/libmarshallers.la

nm-wimax-nsp-glue.h: $(top_srcdir)/introspection/nm-wimax-nsp.xml
	dbus-binding-tool --prefix=nm_wimax_nsp --mode=glib-server --output=$@ $<

nm-wimax-device-glue.h: $(top_srcdir)/introspection/nm-wimax-device.xml
	dbus-binding-tool --prefix=nm_wimax_device --mode=glib-server --output=$@ $<

BUILT_SOURCES = \
	nm-wimax-nsp-glue.h \
	nm-wimax-device-glue.h

CLEANFILES = $(BUILT_SOURCES)
