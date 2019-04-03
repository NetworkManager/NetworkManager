## Process this file with automake to produce Makefile.in
AUTOMAKE_OPTIONS = 1.6

# The name of the module
DOC_MODULE=libnm-glib

# The top-level SGML file.
DOC_MAIN_SGML_FILE=$(DOC_MODULE)-docs.xml

# The directory containing the source code. Relative to $(srcdir).
# gtk-doc will search all .c & .h files beneath here for inline comments
# documenting functions and macros.
DOC_SOURCE_DIR=$(top_srcdir)/libnm-glib

# Extra options to supply to gtkdoc-scan.
SCAN_OPTIONS=

# Extra options to supply to gtkdoc-mkdb.
MKDB_OPTIONS=--sgml-mode --output-format=xml

# Extra options to supply to gtkdoc-fixref.
FIXXREF_OPTIONS=

# Used for dependencies.
HFILE_GLOB=$(top_srcdir)/libnm-glib/*.h
CFILE_GLOB=$(top_srcdir)/libnm-glib/*.c

# Header files to ignore when scanning.
IGNORE_HFILES= \
	common.h \
	nm-dbus-helpers-private.h \
	nm-device-private.h \
	nm-object-cache.h \
	nm-object-private.h \
	nm-remote-connection-private.h \
	nm-types-private.h \
	nm-secret-agent-glue.h \
	nm-vpn-plugin-glue.h

# Images to copy into HTML directory.
HTML_IMAGES = libnm-glib.png

# Extra XML files that are included by $(DOC_MAIN_SGML_FILE).
content_files = version.xml

# Other files to distribute.
extra_files = libnm-glib.png


# CFLAGS and LDFLAGS for compiling scan program. Only needed
# if $(DOC_MODULE).types is non-empty.
GTKDOC_CFLAGS = \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util \
	-I$(top_srcdir)/libnm-glib \
	-I$(top_builddir)/libnm-glib \
	-DNM_VERSION_MIN_REQUIRED=NM_VERSION_0_9_8 \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

GTKDOC_LIBS = \
	$(top_builddir)/libnm-glib/libnm-glib.la \
	$(GLIB_LIBS)


# include common portion ...
include $(top_srcdir)/gtk-doc.make

EXTRA_DIST += version.xml.in meson.build

CLEANFILES += \
	libnm-glib-sections.txt \
	libnm-glib-overrides.txt \
	html/* \
	tmpl/* \
	xml/*

