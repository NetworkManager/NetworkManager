#include "test-common.h"

SignalData *
add_signal_full (const char *name, GCallback callback, int ifindex, const char *ifname)
{
	SignalData *data = g_new0 (SignalData, 1);

	data->name = name;
	data->received = FALSE;
	data->handler_id = g_signal_connect (nm_platform_get (), name, callback, data);
	data->ifindex = ifindex;
	data->ifname = ifname;

	g_assert (data->handler_id >= 0);

	return data;
}

void
accept_signal (SignalData *data)
{
	if (!data->received)
		g_error ("Attemted to accept a non-received signal '%s'.", data->name);

	data->received = FALSE;
}

void
wait_signal (SignalData *data)
{
	data->loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (data->loop);
	g_main_loop_unref (data->loop);
	data->loop = NULL;

	accept_signal (data);
}

void
free_signal (SignalData *data)
{
	if (data->received)
		g_error ("Attempted to free received but not accepted signal '%s'.", data->name);

	g_signal_handler_disconnect (nm_platform_get (), data->handler_id);
	g_free (data);
}

void
run_command (const char *format, ...)
{
	char *command;
	va_list ap;

	va_start (ap, format);

	command = g_strdup_vprintf (format, ap);
	g_assert (!system (command));
	g_free (command);
}

int
main (int argc, char **argv)
{
	int result;

	openlog (G_LOG_DOMAIN, LOG_CONS | LOG_PERROR, LOG_DAEMON);
	g_type_init ();
	g_test_init (&argc, &argv, NULL);
	/* Enable debug messages if called with --debug */
	for (; *argv; argv++) {
		if (!g_strcmp0 (*argv, "--debug")) {
			nm_logging_setup ("debug", NULL, NULL);
		}
	}

	SETUP ();

	setup_tests ();

	result = g_test_run ();

	nm_platform_free ();
	return result;
}
