SUBDIRS = $(TARGET_DISTRO)
DIST_SUBDIRS=RedHat Gentoo Debian Slackware

INCLUDES = 						\
	$(NM_CFLAGS) 			   		\
	-Wall						\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DG_DISABLE_DEPRECATED			\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"

bin_PROGRAMS = NMLaunchHelper

NMLaunchHelper_SOURCES = NMLaunchHelper.c

NMLaunchHelper_LDADD = $(NM_LIBS)
