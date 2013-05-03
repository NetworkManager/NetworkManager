SUBDIRS = . tests

AM_CPPFLAGS = \
	-I${top_srcdir} \
	-I${top_srcdir}/src \
	-I${top_srcdir}/src/logging \
	-I${top_srcdir}/src/generated \
	-I${top_builddir}/src/generated \
	-I${top_srcdir}/libnm-util \
	-DKERNEL_HACKS=1

@GNOME_CODE_COVERAGE_RULES@

noinst_LTLIBRARIES = libnm-platform.la

libnm_platform_la_SOURCES = \
	nm-platform.h \
	nm-platform.c \
	nm-fake-platform.h \
	nm-fake-platform.c \
	nm-linux-platform.h \
	nm-linux-platform.c

libnm_platform_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(GLIB_CFLAGS) \
	$(LIBNL_CFLAGS)

libnm_platform_la_LIBADD = \
	$(top_builddir)/src/logging/libnm-logging.la \
	$(top_builddir)/src/generated/libnm-generated.la \
	$(GLIB_LIBS) \
	$(LIBNL_LIBS)
