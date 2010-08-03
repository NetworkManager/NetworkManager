INCLUDES = \
	-I${top_srcdir}/src \
	-I${top_srcdir}/src/logging \
	-I${top_srcdir}/include \
	-I${top_srcdir}/libnm-util \
	-I${top_builddir}/marshallers

noinst_LTLIBRARIES = libmodem-manager.la

libmodem_manager_la_SOURCES = \
	nm-modem.c \
	nm-modem.h \
	nm-modem-cdma.c \
	nm-modem-cdma.h \
	nm-modem-gsm.c \
	nm-modem-gsm.h \
	nm-modem-manager.h \
	nm-modem-manager.c \
	nm-modem-types.h

libmodem_manager_la_CPPFLAGS = \
	$(DBUS_CFLAGS)

libmodem_manager_la_LIBADD = \
	$(top_builddir)/marshallers/libmarshallers.la \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(DBUS_LIBS)

nm-serial-device-glue.h: $(top_srcdir)/introspection/nm-device-serial.xml
	$(AM_V_GEN) dbus-binding-tool --prefix=nm_serial_device --mode=glib-server --output=$@ $<

BUILT_SOURCES = \
	nm-serial-device-glue.h

CLEANFILES = $(BUILT_SOURCES)
