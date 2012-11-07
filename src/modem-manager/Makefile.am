include $(GLIB_MAKEFILE)

INCLUDES = \
	-I${top_srcdir}/src \
	-I${top_builddir}/src/generated \
	-I${top_srcdir}/src/generated \
	-I${top_srcdir}/src/logging \
	-I${top_builddir}/include \
	-I${top_srcdir}/include \
	-I${top_builddir}/libnm-util \
	-I${top_srcdir}/libnm-util

noinst_LTLIBRARIES = libmodem-manager.la

libmodem_manager_la_SOURCES = \
	nm-modem.c \
	nm-modem.h \
	nm-modem-generic.c \
	nm-modem-generic.h \
	nm-modem-cdma.c \
	nm-modem-cdma.h \
	nm-modem-gsm.c \
	nm-modem-gsm.h \
	nm-modem-manager.h \
	nm-modem-manager.c \
	nm-modem-types.h

libmodem_manager_la_CPPFLAGS = \
	$(LIBNL_CFLAGS) \
	$(DBUS_CFLAGS)

libmodem_manager_la_LIBADD = \
	$(top_builddir)/src/generated/libnm-generated.la \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(LIBNL_LIBS) \
	$(DBUS_LIBS)

# Support for the new ModemManager1 interface
if WITH_MODEM_MANAGER_1
libmodem_manager_la_SOURCES += \
	nm-modem-broadband.h \
	nm-modem-broadband.c
libmodem_manager_la_CPPFLAGS += $(MM_GLIB_CFLAGS)
libmodem_manager_la_LIBADD += $(MM_GLIB_LIBS)
endif
