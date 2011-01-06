INCLUDES = \
	-I${top_srcdir}/src \
	-I${top_srcdir}/src/logging \
	-I${top_srcdir}/include \
	-I${top_srcdir}/libnm-util \
	-I${top_builddir}/marshallers

noinst_LTLIBRARIES = libwimax.la

libwimax_la_SOURCES = \
	nm-device-wimax.c \
	nm-device-wimax.h \
	nm-wimax-nsp.c \
	nm-wimax-nsp.h \
	nm-wimax-types.h \
	nm-wimax-util.c \
	nm-wimax-util.h \
	iwmxsdk.c \
	iwmxsdk.h

libwimax_la_CPPFLAGS = \
	$(DBUS_CFLAGS) \
	$(IWMX_SDK_CFLAGS)

libwimax_la_LIBADD = \
	$(DBUS_LIBS) \
	$(IWMX_SDK_LIBS) \
	$(top_builddir)/marshallers/libmarshallers.la

nm-wimax-nsp-glue.h: $(top_srcdir)/introspection/nm-wimax-nsp.xml
	dbus-binding-tool --prefix=nm_wimax_nsp --mode=glib-server --output=$@ $<

nm-device-wimax-glue.h: $(top_srcdir)/introspection/nm-device-wimax.xml
	dbus-binding-tool --prefix=nm_device_wimax --mode=glib-server --output=$@ $<

BUILT_SOURCES = \
	nm-wimax-nsp-glue.h \
	nm-device-wimax-glue.h

CLEANFILES = $(BUILT_SOURCES)
