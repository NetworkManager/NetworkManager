INCLUDES = -I${top_srcdir} -I${top_srcdir}/libnm_glib

AM_CPPFLAGS =						\
	$(DBUS_CFLAGS)					\
	$(GTHREAD_CFLAGS)				\
	$(HAL_CFLAGS)					\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"

noinst_PROGRAMS = nmtest nminfotest nmtestdevices libnm_glib_test

nmtest_SOURCES = nmclienttest.c
nmtest_LDADD = $(DBUS_LIBS) $(GTHREAD_LIBS) $(HAL_LIBS)

nminfotest_SOURCES = nminfotest.c
nminfotest_LDADD = $(DBUS_LIBS) $(GTHREAD_LIBS)

nmtestdevices_SOURCES = nmtestdevices.c
nmtestdevices_LDADD = $(DBUS_LIBS) $(GTHREAD_LIBS)

libnm_glib_test_SOURCES = libnm_glib_test.c
libnm_glib_test_LDADD = $(DBUS_LIBS) $(GTHREAD_LIBS) -L${top_srcdir}/libnm_glib -lnm_glib
