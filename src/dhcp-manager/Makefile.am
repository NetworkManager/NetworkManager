libexec_PROGRAMS = nm-dhcp-helper

nm_dhcp_helper_SOURCES = nm-dhcp-helper.c

nm_dhcp_helper_CPPFLAGS = $(DBUS_CFLAGS) -DNMRUNDIR=\"$(nmrundir)\"

nm_dhcp_helper_LDADD = $(DBUS_LIBS)


# FIXME: remove when dbus-glib >= 0.100 is required
dbusservicedir = $(DBUS_SYS_DIR)
dbusservice_DATA = nm-dhcp-helper.conf

EXTRA_DIST = $(dbusservice_DATA)

