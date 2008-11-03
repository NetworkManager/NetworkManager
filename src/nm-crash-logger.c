/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2006 - 2008 Red Hat, Inc.
 */


#include <glib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <syslog.h>

int main (int argc, char ** argv)
{
	GPid		gdb_pid;
	int		out;
	char		nm_pid[16];
	char		line[256];
	int		gdb_stat;
	int		bytes_read;
	gboolean	done = FALSE;
	char *	args[] = { BINDIR "/gdb",
                          "--batch", 
                          "--quiet",
                          "--command=" DATADIR "/NetworkManager/gdb-cmd",
                          SBINDIR "/NetworkManager",
                          NULL, NULL };

	snprintf (nm_pid, sizeof (nm_pid), "%d", getppid ());
	args[5] = &nm_pid[0];
	if (!g_spawn_async_with_pipes (NULL, args, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
				       &gdb_pid, NULL, &out, NULL, NULL))
	{
		exit (1);
	}

	openlog ("NetworkManager", LOG_CONS | LOG_PERROR, LOG_DAEMON);
	syslog (LOG_CRIT, "******************* START **********************************");
	while (!done)
	{
		bytes_read = read (out, line, sizeof (line) - 1);
		if (bytes_read > 0)
		{
			char *end = &line[0];
			char *start = &line[0];

			/* Can't just funnel the output to syslog, have to do a separate
			 * syslog () for each line in the output.
			 */
			line[bytes_read] = '\0';
			while (*end != '\0')
			{
				if (*end == '\n')
				{
					*end = '\0';
					syslog (LOG_CRIT, "%s", start);
					start = end + 1;
				}
				end++;
			}
		}
		else if ((bytes_read <= 0) || ((errno != EINTR) && (errno != EAGAIN)))
			done = TRUE;
	}
	syslog (LOG_CRIT, "******************* END **********************************");
	close (out);
	waitpid (gdb_pid, &gdb_stat, 0);
	exit (0);
}
