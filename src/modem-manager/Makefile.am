INCLUDES = \
	-I${top_srcdir}/src \
	-I${top_srcdir}/include \
	-I${top_srcdir}/libnm-util \
	-I${top_builddir}/marshallers

noinst_LTLIBRARIES = libmodem-manager.la

libmodem_manager_la_SOURCES = \
	nm-modem-cdma.c \
	nm-modem-cdma.h \
	nm-modem-gsm.c \
	nm-modem-gsm.h \
	nm-modem-gsm-hso.c \
	nm-modem-gsm-hso.h \
	nm-modem-gsm-mbm.c \
	nm-modem-gsm-mbm.h \
	nm-modem.c \
	nm-modem.h \
	nm-modem-manager.h \
	nm-modem-manager.c \
	nm-modem-types.h

libmodem_manager_la_CPPFLAGS = \
	$(DBUS_CFLAGS)

libmodem_manager_la_LIBADD = \
	$(DBUS_LIBS) \
	$(top_builddir)/marshallers/libmarshallers.la

nm-device-cdma-glue.h: $(top_srcdir)/introspection/nm-device-cdma.xml
	dbus-binding-tool --prefix=nm_device_cdma --mode=glib-server --output=$@ $<

nm-device-gsm-glue.h: $(top_srcdir)/introspection/nm-device-gsm.xml
	dbus-binding-tool --prefix=nm_device_gsm --mode=glib-server --output=$@ $<

nm-serial-device-glue.h: $(top_srcdir)/introspection/nm-device-serial.xml
	dbus-binding-tool --prefix=nm_serial_device --mode=glib-server --output=$@ $<

BUILT_SOURCES = \
	nm-device-cdma-glue.h \
	nm-device-gsm-glue.h \
	nm-serial-device-glue.h

CLEANFILES = $(BUILT_SOURCES)
