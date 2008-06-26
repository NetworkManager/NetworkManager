/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2006 Red Hat, Inc.
 */

#include <syslog.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "nm-logging.h"
#include "nm-utils.h"

static void
fallback_get_backtrace (void)
{
	void *	frames[64];
	size_t	size;
	char **	strings;
	size_t	i;

	size = backtrace (frames, G_N_ELEMENTS (frames));
	if ((strings = backtrace_symbols (frames, size)))
	{
		syslog (LOG_CRIT, "******************* START **********************************");
		for (i = 0; i < size; i++)
			syslog (LOG_CRIT, "Frame %zd: %s", i, strings[i]);
		free (strings);
		syslog (LOG_CRIT, "******************* END **********************************");
	}
	else
	{
		nm_warning ("NetworkManager crashed, but symbols "
					"couldn't be retrieved.");
	}
}


static gboolean
crashlogger_get_backtrace (void)
{
	gboolean success = FALSE;
	int pid;	

	pid = fork();
	if (pid > 0)
	{
		/* Wait for the child to finish */
		int estatus;
		if (waitpid (pid, &estatus, 0) != -1)
		{
			/* Only succeed if the crashlogger succeeded */
			if (WIFEXITED (estatus) && (WEXITSTATUS (estatus) == 0))
				success = TRUE;
		}
	}
	else if (pid == 0)
	{
		/* Child process */
		execl (LIBEXECDIR"/nm-crash-logger",
				LIBEXECDIR"/nm-crash-logger", NULL);
	}

	return success;
}


void
nm_logging_backtrace (void)
{
	struct stat s;
	gboolean fallback = TRUE;
	
	/* Try to use gdb via nm-crash-logger if it exists, since
	 * we get much better information out of it.  Otherwise
	 * fall back to execinfo.
	 */
	if (stat (LIBEXECDIR"/nm-crash-logger", &s) == 0)
		fallback = crashlogger_get_backtrace () ? FALSE : TRUE;

	if (fallback)
		fallback_get_backtrace ();
}


static void
nm_log_handler (const gchar *		log_domain,
			  GLogLevelFlags	log_level,
			  const gchar *	message,
			  gpointer		ignored)
{
	int syslog_priority;	

	switch (log_level)
	{
		case G_LOG_LEVEL_ERROR:
			syslog_priority = LOG_CRIT;
			break;

		case G_LOG_LEVEL_CRITICAL:
			syslog_priority = LOG_ERR;
			break;

		case G_LOG_LEVEL_WARNING:
			syslog_priority = LOG_WARNING;
			break;

		case G_LOG_LEVEL_MESSAGE:
			syslog_priority = LOG_NOTICE;
			break;

		case G_LOG_LEVEL_DEBUG:
			syslog_priority = LOG_DEBUG;
			break;

		case G_LOG_LEVEL_INFO:
		default:
			syslog_priority = LOG_INFO;
			break;
	}

	syslog (syslog_priority, "%s", message);
}


void
nm_logging_setup (gboolean become_daemon)
{
	if (become_daemon)
		openlog (G_LOG_DOMAIN, LOG_CONS, LOG_DAEMON);
	else
		openlog (G_LOG_DOMAIN, LOG_CONS | LOG_PERROR, LOG_USER);

	g_log_set_handler (G_LOG_DOMAIN, 
				    G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
				    nm_log_handler,
				    NULL);
}

void
nm_logging_shutdown (void)
{
	closelog ();
}
