## Process this file with automake to produce Makefile.in
AUTOMAKE_OPTIONS = 1.6

# The name of the module
DOC_MODULE=libnm-glib

# The top-level SGML file.
DOC_MAIN_SGML_FILE=$(DOC_MODULE)-docs.sgml

# The directory containing the source code. Relative to $(srcdir).
# gtk-doc will search all .c & .h files beneath here for inline comments
# documenting functions and macros.
DOC_SOURCE_DIR=../../libnm-glib

# Extra options to supply to gtkdoc-scan.
SCAN_OPTIONS=

# Extra options to supply to gtkdoc-scangobj.
SCANGOBJ_OPTIONS=--type-init-func 'g_type_init();'

# Extra options to supply to gtkdoc-mkdb.
MKDB_OPTIONS=--sgml-mode --output-format=xml

# Extra options to supply to gtkdoc-fixref.
FIXXREF_OPTIONS=

# Used for dependencies.
HFILE_GLOB=$(top_srcdir)/libnm-glib/*.h
CFILE_GLOB=$(top_srcdir)/libnm-glib/*.c

# Header files to ignore when scanning.
IGNORE_HFILES= \
	nm-dbus-utils.h \
	nm-device-private.h \
	nm-object-cache.h \
	nm-object-private.h \
	nm-remote-connection-private.h \
	nm-types-private.h \
	nm-access-point-bindings.h \
	nm-active-connection-bindings.h \
	nm-client-bindings.h \
	nm-device-bindings.h \
	nm-device-bt-bindings.h \
	nm-device-ethernet-bindings.h \
	nm-device-wifi-bindings.h \
	nm-dhcp4-config-bindings.h \
	nm-dhcp6-config-bindings.h \
	nm-exported-connection-bindings.h \
	nm-exported-connection-glue.h \
	nm-ip4-config-bindings.h \
	nm-ip6-config-bindings.h \
	nm-settings-bindings.h \
	nm-settings-glue.h \
	nm-settings-system-bindings.h \
	nm-vpn-connection-bindings.h \
	nm-vpn-plugin-glue.h

# Images to copy into HTML directory.
HTML_IMAGES = 

# Extra XML files that are included by $(DOC_MAIN_SGML_FILE).
content_files = 

# Other files to distribute.
extra_files =


# CFLAGS and LDFLAGS for compiling scan program. Only needed
# if $(DOC_MODULE).types is non-empty.
GTKDOC_CFLAGS =				\
	-I$(top_srcdir)/include		\
	-I$(top_srcdir)/libnm-util	\
	-I$(top_builddir)/marshallers	\
	-I$(top_srcdir)/libnm-glib	\
	$(GLIB_CFLAGS)			\
	$(DBUS_CFLAGS)

GTKDOC_LIBS = $(top_builddir)/libnm-glib/libnm-glib.la


# include common portion ...
include $(top_srcdir)/gtk-doc.make

CLEANFILES += libnm-glib-sections.txt

