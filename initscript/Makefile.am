SUBDIRS = 
if TARGET_REDHAT
SUBDIRS += RedHat
endif
if TARGET_GENTOO
SUBDIRS += Gentoo
endif
if TARGET_DEBIAN
SUBDIRS += Debian
endif
if TARGET_SLACKWARE
SUBDIRS += Slackware
endif

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
