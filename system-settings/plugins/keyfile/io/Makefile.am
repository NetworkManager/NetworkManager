INCLUDES = \
	-I$(top_srcdir)/system-settings/src \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_srcdir)/libnm-glib

noinst_LTLIBRARIES = libkeyfile-io.la

libkeyfile_io_la_SOURCES = \
	reader.h \
	reader.c \
	writer.h \
	writer.c

libkeyfile_io_la_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

libkeyfile_io_la_LIBADD = $(GLIB_LIBS)

