INCLUDES = -I${top_srcdir}                    \
           -I${top_srcdir}/include            \
           -I${top_srcdir}/libnm-util         \
           -I${top_srcdir}/test               \
           -I${top_srcdir}/test/test-common

noinst_PROGRAMS = test-dbus-dict-helpers

test_dbus_dict_helpers_SOURCES = test-dbus-dict-helpers.c

test_dbus_dict_helpers_CPPFLAGS =		\
	$(DBUS_CFLAGS)					\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"

test_dbus_dict_helpers_LDADD = \
          $(DBUS_LIBS)    \
		$(top_builddir)/libnm-util/libnm-util.la \
		$(top_builddir)/test/test-common/libtest-common.la
