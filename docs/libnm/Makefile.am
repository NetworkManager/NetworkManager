## Process this file with automake to produce Makefile.in
AUTOMAKE_OPTIONS = 1.6

# The name of the module
DOC_MODULE=libnm

# The top-level SGML file.
DOC_MAIN_SGML_FILE=$(DOC_MODULE)-docs.xml

# The directory containing the source code. Relative to $(srcdir).
# gtk-doc will search all .c & .h files beneath here for inline comments
# documenting functions and macros.
DOC_SOURCE_DIR= \
	$(top_srcdir)/libnm-core \
	$(top_builddir)/libnm-core \
	$(top_srcdir)/libnm \
	$(top_builddir)/libnm

# Extra options to supply to gtkdoc-scan.
SCAN_OPTIONS=--rebuild-types --rebuild-sections

# Extra options to supply to gtkdoc-scangobj.
SCANGOBJ_OPTIONS=--type-init-func 'g_type_init();'

# Extra options to supply to gtkdoc-mkdb.
MKDB_OPTIONS=--sgml-mode --output-format=xml

# Extra options to supply to gtkdoc-fixref.
FIXXREF_OPTIONS=

# Used for dependencies.
HFILE_GLOB=$(top_srcdir)/libnm-core/*.h $(top_srcdir)/libnm/*.h
CFILE_GLOB=$(top_srcdir)/libnm-core/*.c $(top_srcdir)/libnm/*.c

# Header files to ignore when scanning.
IGNORE_HFILES= \
	common.h \
	crypto.h \
	nm-dbus-helpers.h \
	nm-core-internal.h \
	nm-core-types-internal.h \
	nm-device-private.h \
	nm-dhcp4-config.h \
	nm-dhcp6-config.h \
	nm-ip4-config.h \
	nm-ip6-config.h \
	nm-manager.h \
	nm-object-cache.h \
	nm-object-private.h \
	nm-property-compare.h \
	nm-remote-connection-private.h \
	nm-remote-settings.h \
	nm-setting-private.h \
	nm-utils-private.h \
	nm-core-tests-enum-types.h \
	nm-keyfile-internal.h \
	nm-keyfile-utils.h \
	test-general-enums.h

# Images to copy into HTML directory.
HTML_IMAGES = libnm.png

# Extra XML files that are included by $(DOC_MAIN_SGML_FILE).
content_files = version.xml

# Other files to distribute.
extra_files = libnm.png


# CFLAGS and LDFLAGS for compiling scan program. Only needed
# if $(DOC_MODULE).types is non-empty.
GTKDOC_CFLAGS =				\
	-I$(top_srcdir)/libnm-core	\
	-I$(top_builddir)/libnm-core	\
	-I$(top_srcdir)/libnm		\
	-I$(top_builddir)/libnm		\
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	-DNM_VERSION_MIN_REQUIRED=NM_VERSION_0_9_8 \
	$(GLIB_CFLAGS)

GTKDOC_LIBS =  \
	$(top_builddir)/libnm/libnm.la \
	$(GLIB_LIBS)


# include common portion ...
include $(top_srcdir)/gtk-doc.make

EXTRA_DIST += version.xml.in

CLEANFILES += \
	libnm-sections.txt \
	libnm-overrides.txt \
	html/* \
	tmpl/* \
	xml/*

