dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = nm-dhcp-client.conf

libexec_PROGRAMS = nm-dhcp-client.action

nm_dhcp_client_action_SOURCES = \
	nm-dhcp-client-action.c

nm_dhcp_client_action_CPPFLAGS = 		\
	$(DBUS_CFLAGS)						\
	$(GTHREAD_CFLAGS)					\
	-DDBUS_API_SUBJECT_TO_CHANGE		\
	-DG_DISABLE_DEPRECATED				\
	-DSYSCONFDIR=\"$(sysconfdir)\"		\
	-DLIBEXECDIR=\"$(libexecdir)\"

nm_dhcp_client_action_LDADD = 	\
			$(DBUS_LIBS)		\
			$(GTHREAD_LIBS)

EXTRA_DIST = $(dbusservice_DATA)
