INCLUDES =						\
	$(NM_CFLAGS)					\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"

noinst_PROGRAMS = nmtest nminfotest

nmtest_SOURCES = nmclienttest.c
nmtest_LDADD = $(NM_LIBS)

nminfotest_SOURCES = nminfotest.c
nminfotest_LDADD = $(NM_LIBS)
