INCLUDES = -I${top_srcdir}

CPPFLAGS =						\
	$(NM_CFLAGS)					\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"

noinst_PROGRAMS = nmtest nminfotest nmtestdevices

nmtest_SOURCES = nmclienttest.c
nmtest_LDADD = $(NM_LIBS)

nminfotest_SOURCES = nminfotest.c
nminfotest_LDADD = $(NM_LIBS)

nmtestdevices_SOURCES = nmtestdevices.c
nmtestdevices_LDADD = $(NM_LIBS)
