## Process this file with automake to produce Makefile.in
AUTOMAKE_OPTIONS = 1.6

check_local =

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
SCAN_OPTIONS=--rebuild-types --rebuild-sections --ignore-decorators="NM_AVAILABLE_IN_\d_\d\d?|NM_DEPRECATED_IN_\d_\d\d?"

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
	nm-core-internal.h \
	nm-core-tests-enum-types.h \
	nm-core-types-internal.h \
	nm-crypto-impl.h \
	nm-crypto.h \
	nm-dbus-helpers.h \
	nm-device-private.h \
	nm-dhcp4-config.h \
	nm-dhcp6-config.h \
	nm-dns-manager.h \
	nm-ip4-config.h \
	nm-ip6-config.h \
	nm-manager.h \
	nm-object-private.h \
	nm-property-compare.h \
	nm-remote-connection-private.h \
	nm-setting-private.h \
	nm-utils-private.h \
	\
	test-general-enums.h \
	\
	nm-keyfile-internal.h \
	nm-keyfile-utils.h \
	\
	nm-auth-subject.h \
	nm-common-macros.h \
	nm-ethtool-utils.h \
	nm-libnm-core-utils.h \
	\
	nm-dispatcher-api.h \
	nm-libnm-core-aux.h \
	\
	$(NULL)

# Images to copy into HTML directory.
HTML_IMAGES = libnm.png

# Extra XML files that are included by $(DOC_MAIN_SGML_FILE).
content_files = version.xml

# Other files to distribute.
extra_files = libnm.png


# CFLAGS and LDFLAGS for compiling scan program. Only needed
# if $(DOC_MODULE).types is non-empty.
GTKDOC_CFLAGS = \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/libnm \
	-I$(top_builddir)/libnm \
	-DNM_VERSION_MIN_REQUIRED=NM_VERSION_0_9_8 \
	$(GLIB_CFLAGS) \
	$(SANITIZER_EXEC_CFLAGS)

GTKDOC_LIBS = \
	$(top_builddir)/libnm/libnm.la \
	$(GLIB_LIBS) \
	$(SANITIZER_EXEC_LDFLAGS)


# include common portion ...
include $(top_srcdir)/gtk-doc.make

EXTRA_DIST += version.xml.in meson.build

CLEANFILES += \
	libnm-sections.txt \
	libnm-overrides.txt \
	html/* \
	tmpl/* \
	xml/*

if GTK_DOC_BUILD_HTML
check-local-gtk-doc-patch:
	@if grep -q -F '<a href="libnm-nm-setting-user.html">nm-setting-user</a>' "$(top_builddir)/docs/libnm/html/index.html"; then \
		echo "WARNING: The generated documentation has issues. Patch your gtk-doc (see https://gitlab.gnome.org/GNOME/gtk-doc/merge_requests/2). Let this check fail with NMTST_CHECK_GTK_DOC=1"; \
		test "$$NMTST_CHECK_GTK_DOC" != 1; \
	fi
check_local += check-local-gtk-doc-patch
endif

check-local: $(check_local)
