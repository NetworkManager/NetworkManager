#include <sys/types.h>

#include <sys/socket.h>
#include <asm/types.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <errno.h>

#include <glib.h>
#include <nm-netlink-monitor.h>

static void
device_added (NmNetlinkMonitor *monitor,
	      const gchar      *device_name)
{
	g_print ("interface '%s' connected\n", device_name);
}


static void
device_removed (NmNetlinkMonitor *monitor,
	        const gchar      *device_name)
{
	g_print ("interface '%s' disconnected\n", device_name);
}

int
main (void)
{
	NmNetlinkMonitor *monitor;
	GMainLoop *loop;
	GError *error;

	g_type_init ();

	monitor = nm_netlink_monitor_new ();

	error = NULL;
	nm_netlink_monitor_open_connection (monitor, &error);

	if (error != NULL)
	{
		g_printerr ("could not open connection: %s\n",
			    error->message);
		g_error_free (error);
		return 1;
	}

	loop = g_main_loop_new (NULL, FALSE);

	g_signal_connect (G_OBJECT (monitor),
			  "interface-connected",
			  G_CALLBACK (device_added), NULL);

	g_signal_connect (G_OBJECT (monitor),
			  "interface-disconnected",
			  G_CALLBACK (device_removed), NULL);

	nm_netlink_monitor_attach (monitor, NULL);

	nm_netlink_monitor_request_status (monitor, &error);

	if (error != NULL)
	{
		g_printerr ("could not request status of interfaces: %s\n",
			    error->message);
		g_error_free (error);
		return 2;
	}

	g_main_loop_run (loop);

	return 0;
}
