## Process this file with automake to produce Makefile.in
AUTOMAKE_OPTIONS = 1.6

# The name of the module
DOC_MODULE=libnm-util

# The top-level SGML file.
DOC_MAIN_SGML_FILE=$(DOC_MODULE)-docs.sgml

# The directory containing the source code. Relative to $(srcdir).
# gtk-doc will search all .c & .h files beneath here for inline comments
# documenting functions and macros.
DOC_SOURCE_DIR= \
	$(top_builddir)/libnm-util \
	$(top_srcdir)/libnm-util

# Extra options to supply to gtkdoc-scan.
SCAN_OPTIONS=--rebuild-types --rebuild-sections

# Extra options to supply to gtkdoc-mkdb.
MKDB_OPTIONS=--sgml-mode --output-format=xml

# Extra options to supply to gtkdoc-fixref.
FIXXREF_OPTIONS=

# Used for dependencies.
HFILE_GLOB=$(top_srcdir)/libnm-util/*.h
CFILE_GLOB=$(top_srcdir)/libnm-util/*.c

# Header files to ignore when scanning.
IGNORE_HFILES= \
	crypto.h \
	nm-utils-private.h \
	nm-setting-private.h \
	nm-param-spec-specialized.h \
	nm-test-utils.h \
	nm-version.h

# Images to copy into HTML directory.
HTML_IMAGES =

# Extra XML files that are included by $(DOC_MAIN_SGML_FILE).
content_files = version.xml

# Other files to distribute.
extra_files =


# CFLAGS and LDFLAGS for compiling scan program. Only needed
# if $(DOC_MODULE).types is non-empty.
GTKDOC_CFLAGS = \
	-I$(top_srcdir)/libnm-util \
	-DNM_VERSION_MIN_REQUIRED=NM_VERSION_0_9_8 \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

GTKDOC_LIBS = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS)



# include common portion ...
include $(top_srcdir)/gtk-doc.make

EXTRA_DIST += version.xml.in meson.build

CLEANFILES += \
	libnm-util-sections.txt \
	libnm-util-overrides.txt \
	html/* \
	tmpl/* \
	xml/*

