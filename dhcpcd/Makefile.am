INCLUDES = -I${top_srcdir} -I${top_srcdir}/src

AM_CPPFLAGS =						\
	$(NM_CFLAGS)					\
	-DBINDIR=\"$(bindir)\"			\
	-DDATADIR=\"$(datadir)\"

noinst_LIBRARIES = libdhcpc.a

libdhcpc_a_SOURCES=	\
	buildmsg.c	\
	buildmsg.h	\
	arp.c		\
	arp.h		\
	client.c		\
	client.h		\
	dhcpcd.c		\
	dhcpcd.h

bin_PROGRAMS = dhcp_test
dhcp_test_SOURCES = dhcp_test.c
dhcp_test_LDADD = libdhcpc.a
