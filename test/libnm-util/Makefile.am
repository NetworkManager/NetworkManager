INCLUDES = -I${top_srcdir}                    \
           -I${top_srcdir}/utils              \
           -I${top_srcdir}/include            \
           -I${top_srcdir}/libnm-util         \
           -I${top_srcdir}/test               \
           -I${top_srcdir}/test/test-common

noinst_PROGRAMS = test-ciphers test-dbus-helpers

test_ciphers_SOURCES = test-ciphers.c test-inputs.h

test_ciphers_CPPFLAGS =		\
	$(DBUS_CFLAGS)					\
	$(GLIB_CFLAGS)					\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"

test_ciphers_LDADD = \
          $(DBUS_LIBS)    \
          $(GLIB_LIBS)    \
          $(top_builddir)/libnm-util/libnm-util.la \
          $(top_builddir)/test/test-common/libtest-common.la

test_dbus_helpers_SOURCES = test-dbus-helpers.c test-inputs.h

test_dbus_helpers_CPPFLAGS =		\
	$(DBUS_CFLAGS)					\
	$(GLIB_CFLAGS)					\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"

test_dbus_helpers_LDADD = \
          $(DBUS_LIBS)    \
          $(GLIB_LIBS)    \
		$(top_builddir)/libnm-util/libnm-util.la \
		$(top_builddir)/test/test-common/libtest-common.la
