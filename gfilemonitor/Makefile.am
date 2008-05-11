INCLUDES = -I${top_srcdir}/include -I${top_builddir}/marshallers

noinst_LTLIBRARIES = libgfilemonitor.la

libgfilemonitor_la_SOURCES = \
	gfile.c \
	gfile.h \
	gfilemonitor.c \
	gfilemonitor.h \
	glocalfilemonitor.c \
	glocalfilemonitor.h \
	glocaldirectorymonitor.c \
	glocaldirectorymonitor.h \
	inotify-diag.c \
	inotify-diag.h \
	inotify-helper.c \
	inotify-helper.h \
	inotify-kernel.c \
	inotify-kernel.h \
	inotify-missing.c \
	inotify-missing.h \
	inotify-path.c \
	inotify-path.h \
	inotify-sub.c \
	inotify-sub.h

libgfilemonitor_la_CPPFLAGS = $(GTHREAD_CFLAGS)

libgfilemonitor_la_LIBADD = $(GTHREAD_LIBS)
