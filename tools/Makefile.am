GENERATE_SETTINGS_SPEC_SOURCE = generate-settings-spec.c

INCLUDES = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libnm-util \
	-I$(top_builddir)/libnm-util

noinst_PROGRAMS = \
	generate-settings-spec

generate_settings_spec_SOURCES = \
	$(GENERATE_SETTINGS_SPEC_SOURCE)

generate_settings_spec_CPPFLAGS = \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS)

generate_settings_spec_LDADD = \
	$(top_builddir)/libnm-util/libnm-util.la \
	$(GLIB_LIBS) \
	$(DBUS_LIBS)

EXTRA_DIST = \
	doc-generator.xsl \
	check-exports.sh \
	$(GENERATE_SETTINGS_SPEC_SOURCE)
