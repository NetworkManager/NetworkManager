/*
 *  Copyright (C) 2004 Red Hat, Inc.
 *
 *  Written by Colin Walters <walters@redhat.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include "config.h"
#include "nm-named-manager.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ftw.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <resolv.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <syslog.h>
#include <glib.h>

#ifndef RESOLV_CONF
#define RESOLV_CONF "/etc/resolv.conf"
#endif

G_DEFINE_TYPE(NMNamedManager, nm_named_manager, G_TYPE_OBJECT)

static void nm_named_manager_finalize (GObject *object);
static void nm_named_manager_dispose (GObject *object);
static GObject *nm_named_manager_constructor (GType type, guint n_construct_properties,
					      GObjectConstructParam *construct_properties);
static gboolean rewrite_resolv_conf (NMNamedManager *mgr, GError **error);
static int safer_kill (const char *path, pid_t pid, int signum);

struct NMNamedManagerPrivate
{
	char *named_realpath_binary;
	GPid named_pid;
	guint spawn_count;
	guint child_watch_id;
	guint queued_reload_id;

	guint id_serial;
	GHashTable *domain_searches; /* guint -> char * */
	GHashTable *global_ipv4_nameservers; /* guint -> char * */
	GHashTable *domain_ipv4_nameservers; /* char * -> GHashTable(guint -> char *) */

	char *named_conf;
	char *named_pid_file;

	gboolean disposed;
};

static void
nm_named_manager_class_init (NMNamedManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = nm_named_manager_dispose;
	object_class->finalize = nm_named_manager_finalize;
	object_class->constructor = nm_named_manager_constructor;
}

static void
nm_named_manager_init (NMNamedManager *mgr)
{
	mgr->priv = g_new0 (NMNamedManagerPrivate, 1);

	mgr->priv->domain_searches = g_hash_table_new_full (NULL, NULL,
							    NULL,  (GDestroyNotify) g_free);
	mgr->priv->global_ipv4_nameservers = g_hash_table_new_full (NULL, NULL,
								    NULL,  (GDestroyNotify) g_free);
	mgr->priv->domain_ipv4_nameservers = g_hash_table_new_full (g_str_hash, g_str_equal,
								    g_free,
								    (GDestroyNotify) g_hash_table_destroy);
}

static void
nm_named_manager_dispose (GObject *object)
{
	NMNamedManager *mgr = NM_NAMED_MANAGER (object);

	if (mgr->priv->disposed)
		return;
	mgr->priv->disposed = TRUE;

	if (mgr->priv->named_conf)
		unlink (mgr->priv->named_conf);
	if (mgr->priv->named_pid_file)
		unlink (mgr->priv->named_pid_file);
	if (mgr->priv->named_realpath_binary)
		safer_kill (mgr->priv->named_realpath_binary, mgr->priv->named_pid, SIGTERM);
	if (mgr->priv->child_watch_id)
		g_source_remove (mgr->priv->child_watch_id);

}

static void
nm_named_manager_finalize (GObject *object)
{
	NMNamedManager *mgr = NM_NAMED_MANAGER (object);

	g_return_if_fail (mgr->priv != NULL);

	g_hash_table_destroy (mgr->priv->domain_searches);
	g_hash_table_destroy (mgr->priv->global_ipv4_nameservers);
	g_hash_table_destroy (mgr->priv->domain_ipv4_nameservers);

	g_free (mgr->priv->named_pid_file);
	g_free (mgr->priv->named_conf);

	g_free (mgr->priv);

	G_OBJECT_CLASS (nm_named_manager_parent_class)->finalize (object);
}

static GObject *
nm_named_manager_constructor (GType type, guint n_construct_properties,
			      GObjectConstructParam *construct_properties)
{
	NMNamedManager *mgr;
	NMNamedManagerClass *klass;
	GObjectClass *parent_class;  

	klass = NM_NAMED_MANAGER_CLASS (g_type_class_peek (NM_TYPE_NAMED_MANAGER));

	parent_class = G_OBJECT_CLASS (g_type_class_peek_parent (klass));
	mgr = NM_NAMED_MANAGER (parent_class->constructor (type, n_construct_properties,
							  construct_properties));


	return G_OBJECT (mgr);
}

NMNamedManager *
nm_named_manager_new (void)
{
	return NM_NAMED_MANAGER (g_object_new (NM_TYPE_NAMED_MANAGER, NULL));
}

GQuark
nm_named_manager_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm_named_manager_error");

	return quark;
}

static void
join_forwarders (gpointer key, gpointer value, gpointer data)
{
	guint id = GPOINTER_TO_UINT (key);
	const char *server = value;
	GString *str = data;

	g_string_append_c (str, ' ');
	g_string_append (str, server);
	g_string_append_c (str, ';');
}

static char *
compute_global_forwarders (NMNamedManager *mgr)
{
	GString *str = g_string_new ("");

	g_hash_table_foreach (mgr->priv->global_ipv4_nameservers,
			      join_forwarders,
			      str);
	return g_string_free (str, FALSE);
}

static void
compute_zone (gpointer key, gpointer value, gpointer data)
{
	const char *domain = key;
	GHashTable *servers = value;
	GString *str = data;

	g_string_append_c (str, '\n');
	g_string_append (str, " zone \"");
	g_string_append (str, domain);
	g_string_append (str, "\"\n");
	g_string_append (str, " forwarders {");

	g_hash_table_foreach (servers, join_forwarders, str);
	g_string_append (str, "}\n}\n");
}

static char *
compute_domain_zones (NMNamedManager *mgr)
{
	GString *str = g_string_new ("");

	g_hash_table_foreach (mgr->priv->domain_ipv4_nameservers,
			      compute_zone,
			      str);
	return g_string_free (str, FALSE);
}

gboolean
generate_named_conf (NMNamedManager *mgr, GError **error)
{
#ifndef NM_NO_NAMED
	char *filename = NULL;
	int out_fd;
	char *config_contents_str;
	char **config_contents;
	char **line;
	const char *config_name;

	config_name = NM_PKGDATADIR "/named.conf";

	if (!mgr->priv->named_conf)
	{
		mgr->priv->named_conf = g_build_filename (NM_NAMED_DATA_DIR,
							  "NetworkManager-named.conf",
							  NULL);
		unlink (mgr->priv->named_conf);
		out_fd = open (mgr->priv->named_conf, O_CREAT|O_EXCL, 0600);
		if (out_fd < 0)
		{
			g_set_error (error,
				     G_FILE_ERROR,
				     G_FILE_ERROR_EXIST,
				     "Couldn't create %s: %s",
				     mgr->priv->named_conf,
				     g_strerror (errno));
			return FALSE;
		}
		close (out_fd);
	}

	if (!mgr->priv->named_pid_file)
	{
		mgr->priv->named_pid_file = g_build_filename (NM_NAMED_DATA_DIR,
							      "NetworkManager-pid-named",
							      NULL);
		unlink (mgr->priv->named_pid_file);
		out_fd = open (mgr->priv->named_pid_file, O_CREAT|O_EXCL, 0600);
		if (out_fd < 0)
		{
			g_set_error (error,
				     G_FILE_ERROR,
				     G_FILE_ERROR_EXIST,
				     "Couldn't create %s: %s",
				     mgr->priv->named_pid_file,
				     g_strerror (errno));
			return FALSE;
		}
		close (out_fd);
	}

	if (!g_file_get_contents (config_name,
				  &config_contents_str,
				  NULL,
				  error))
	{
		return FALSE;
	}

	out_fd = g_file_open_tmp ("NetworkManager-named.conf-XXXXXX",
				  &filename,
				  error);

	if (out_fd < 0)
	{
		g_free (config_contents_str);
		return FALSE;
	}

	config_contents = g_strsplit (config_contents_str,
				      "\n",
				      0);
	g_free (config_contents_str);

	for (line = config_contents; *line; line++)
	{
		const char *variable_pos;
		const char *variable_end_pos;

		if ((variable_pos = strstr (*line, "@@"))
		    && (variable_end_pos = strstr (variable_pos + 2, "@@")))
		{
			char *variable;
			char *replacement = NULL;

			variable = g_strndup (variable_pos + 2,
					      variable_end_pos - (variable_pos + 2));
			if (strcmp ("LOCALSTATEDIR", variable) == 0)
				replacement = g_strdup (NM_LOCALSTATEDIR);
			else if (strcmp ("PID_FILE", variable) == 0)
				replacement = g_strdup (mgr->priv->named_pid_file);
			else if (strcmp ("FORWARDERS", variable) == 0)
				replacement = compute_global_forwarders (mgr);
			else if (strcmp ("DOMAIN_ZONES", variable) == 0)
				replacement = compute_domain_zones (mgr);
			else
			{
				syslog (LOG_WARNING, "Unknown variable %s in %s",
					   variable, config_name);
				if (write (out_fd, *line, strlen (*line)) < 0)
					goto replacement_lose;
			}

			if (write (out_fd, *line, variable_pos - *line) < 0)
				goto replacement_lose;
			if (write (out_fd, replacement, strlen (replacement)) < 0)
				goto replacement_lose;
			if (write (out_fd, variable_end_pos + 2, strlen (variable_end_pos + 2)) < 0)
				goto replacement_lose;
			if (write (out_fd, "\n", 1) < 0)
				goto replacement_lose;

			g_free (variable);
			g_free (replacement);
			continue;
		replacement_lose:
			g_free (variable);
			g_free (replacement);
			goto write_lose;
		} else {
			if (write (out_fd, *line, strlen (*line)) < 0)
				goto write_lose;
				
		}
		if (write (out_fd, "\n", 1) < 0)
			goto write_lose;
	}
	
	close (out_fd);

	if (rename (filename, mgr->priv->named_conf) < 0) {
		g_set_error (error,
			     NM_NAMED_MANAGER_ERROR,
			     NM_NAMED_MANAGER_ERROR_SYSTEM,
			     "Couldn't rename %s to %s: %s",
			     filename, mgr->priv->named_conf,
			     g_strerror (errno));
		return FALSE;
	}

	g_strfreev (config_contents);
	return TRUE;
write_lose:
	close (out_fd);
	g_strfreev (config_contents);
	unlink (filename);
	g_free (filename);
	return FALSE;
#else
	return rewrite_resolv_conf (mgr, error);
#endif
}

static void
watch_cb (GPid pid, gint status, gpointer data)
{
	NMNamedManager *mgr = NM_NAMED_MANAGER (data);

	if (WIFEXITED (status))
		syslog (LOG_WARNING, "named exited with error code %d", WEXITSTATUS (status));
	else if (WIFSTOPPED (status)) 
		syslog (LOG_WARNING, "named stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		syslog (LOG_WARNING, "named died with signal %d", WTERMSIG (status));
	else
		syslog (LOG_WARNING, "named died from an unknown cause");

	if (mgr->priv->queued_reload_id > 0)
		g_source_remove (mgr->priv->queued_reload_id);
	
	/* FIXME - do something with error; need to handle failure to
	 * respawn */
	nm_named_manager_start (mgr, NULL);
}

gboolean
nm_named_manager_start (NMNamedManager *mgr, GError **error)
{
#ifndef NM_NO_NAMED
	GPid pid;
	const char *named_binary;
	GPtrArray *named_argv;

	mgr->priv->named_pid = 0;

	mgr->priv->spawn_count++;
	if (mgr->priv->spawn_count > 5)
	{
		g_set_error (error,
			     NM_NAMED_MANAGER_ERROR,
			     NM_NAMED_MANAGER_ERROR_SYSTEM,
			     "named crashed more than 5 times, refusing to try again");
		return FALSE;
	}

	if (!generate_named_conf (mgr, error))
		return FALSE;

	named_argv = g_ptr_array_new ();
	named_binary = g_getenv ("NM_NAMED_BINARY_PATH") ?
	  g_getenv ("NM_NAMED_BINARY_PATH") : NM_NAMED_BINARY_PATH;
	g_free (mgr->priv->named_realpath_binary);
	mgr->priv->named_realpath_binary = realpath (named_binary, NULL);
	if (mgr->priv->named_realpath_binary == NULL)
		mgr->priv->named_realpath_binary = g_strdup (named_binary);
	g_ptr_array_add (named_argv, (char *) named_binary);
	g_ptr_array_add (named_argv, "-f");
	g_ptr_array_add (named_argv, "-c");
	g_ptr_array_add (named_argv, mgr->priv->named_conf);
	g_ptr_array_add (named_argv, NULL);

	if (!g_spawn_async (NULL, (char **) named_argv->pdata, NULL,
			    G_SPAWN_LEAVE_DESCRIPTORS_OPEN |
			    G_SPAWN_DO_NOT_REAP_CHILD,
			    NULL, NULL, &pid,
			    error))
	{
		g_ptr_array_free (named_argv, TRUE);
		return FALSE;
	}
	g_ptr_array_free (named_argv, TRUE);
	mgr->priv->named_pid = pid;
	if (mgr->priv->child_watch_id)
		g_source_remove (mgr->priv->child_watch_id);
	mgr->priv->child_watch_id = g_child_watch_add (pid, watch_cb, mgr);

#endif
	if (!rewrite_resolv_conf (mgr, error))
	{
		safer_kill (mgr->priv->named_realpath_binary, mgr->priv->named_pid, SIGTERM);
		return FALSE;
	}

	return TRUE;
}

static gboolean
reload_named (NMNamedManager *mgr, GError **error)
{
	/* FIXME - handle error */
	if (!generate_named_conf (mgr, error))
		return FALSE;
#ifndef NM_NO_NAMED
	if (safer_kill (mgr->priv->named_realpath_binary, mgr->priv->named_pid, SIGHUP) < 0) {
		g_set_error (error,
			     NM_NAMED_MANAGER_ERROR,
			     NM_NAMED_MANAGER_ERROR_SYSTEM,
			     "Couldn't signal nameserver: %s",
			     g_strerror (errno));
		return FALSE;
	}
#endif
	return TRUE;
}

static gboolean
validate_host (const char *server, GError **error)
{
	for (; *server; server++)
	{
		if (!(g_ascii_isalpha (*server)
		      || g_ascii_isdigit (*server)
		      || *server == '-'
		      || *server == '.'))
		{
			g_set_error (error,
				     NM_NAMED_MANAGER_ERROR,
				     NM_NAMED_MANAGER_ERROR_INVALID_HOST,
				     "Invalid characters in host");
			return FALSE;
		}
	}
	return TRUE;
}

static void
compute_search (gpointer key, gpointer value, gpointer data)
{
	const char *server = value;
	GString *str = data;

	g_string_append (str, "search ");
	g_string_append (str, server);
	g_string_append_c (str, '\n');
}

static char *
compute_domain_searches (NMNamedManager *mgr)
{
	GString *str = g_string_new ("");

	g_hash_table_foreach (mgr->priv->domain_searches,
			      compute_search,
			      str);
	return g_string_free (str, FALSE);
}

#ifdef NM_NO_NAMED
static void
write_nameserver (gpointer key, gpointer value, gpointer data)
{
	guint id = GPOINTER_TO_UINT (key);
	const char *server = value;
	FILE *f = data;

	fprintf (f, "nameserver %s\n", server);
	
}
#endif

static gboolean
rewrite_resolv_conf (NMNamedManager *mgr, GError **error)
{
	const char *tmp_resolv_conf = RESOLV_CONF ".tmp";
	char *searches;
	FILE *f;

	if ((f = fopen (tmp_resolv_conf, "w")) == NULL)
		goto lose;
	
	searches = compute_domain_searches (mgr);
	if (fprintf (f, "%s"," ; generated by NetworkManager, do not edit!\n") < 0) {
		g_free (searches);
		goto lose;
	}
#ifndef NM_NO_NAMED
	if (fprintf (f, "%s%s%s", "; Use a local caching nameserver controlled by NetworkManager\n", searches, "\nnameserver 127.0.0.1\n") < 0) {
		goto lose;
	}
#else
	g_hash_table_foreach (mgr->priv->global_ipv4_nameservers,
			      write_nameserver,
			      f);
#endif
	g_free (searches);
	if (fclose (f) < 0)
		goto lose;

	if (rename (tmp_resolv_conf, RESOLV_CONF) < 0)
		goto lose;
	return TRUE;
 lose:
	g_set_error (error,
		     NM_NAMED_MANAGER_ERROR,
		     NM_NAMED_MANAGER_ERROR_SYSTEM,
		     "Could not update " RESOLV_CONF ": %s\n", g_strerror (errno));
	return FALSE;
}

guint
nm_named_manager_add_domain_search (NMNamedManager *mgr,
				    const char *domain,
				    GError **error)
{
	guint id;

	if (!validate_host (domain, error))
		return 0;

	id = ++mgr->priv->id_serial;

	g_hash_table_insert (mgr->priv->domain_searches,
			     GUINT_TO_POINTER (id),
			     g_strdup (domain));
	if (!rewrite_resolv_conf (mgr, error)) {
		g_hash_table_remove (mgr->priv->global_ipv4_nameservers,
				     GUINT_TO_POINTER (id));
		return 0;
	}
	return id;
}

gboolean
nm_named_manager_remove_domain_search (NMNamedManager *mgr,
				       guint id,
				       GError **error)
{
	if (!g_hash_table_remove (mgr->priv->domain_searches,
				  GUINT_TO_POINTER (id)))
	{
		g_set_error (error,
			     NM_NAMED_MANAGER_ERROR,
			     NM_NAMED_MANAGER_ERROR_INVALID_ID,
			     "Invalid domain search id");
		return FALSE;
	}
	if (!rewrite_resolv_conf (mgr, error))
		return FALSE;
	return TRUE;
}

guint
nm_named_manager_add_nameserver_ipv4 (NMNamedManager *mgr,
				      const char *server,
				      GError **error)
{
	guint id;

	if (!validate_host (server, error))
		return 0;

	id = ++mgr->priv->id_serial;

	g_hash_table_insert (mgr->priv->global_ipv4_nameservers,
			     GUINT_TO_POINTER (id),
			     g_strdup (server));
	if (!reload_named (mgr, error)) {
		g_hash_table_remove (mgr->priv->global_ipv4_nameservers,
				     GUINT_TO_POINTER (id));
		return 0;
	}
	return id;
}

guint
nm_named_manager_add_domain_nameserver_ipv4 (NMNamedManager *mgr,
					     const char *domain,
					     const char *server,
					     GError **error)
{
	GHashTable *servers;
	guint id;

	if (!validate_host (server, error))
		return 0;

	id = ++mgr->priv->id_serial;

	servers = g_hash_table_lookup (mgr->priv->domain_ipv4_nameservers,
				       domain);
	if (!servers)
	{
		servers = g_hash_table_new_full (NULL, NULL,
						 NULL, (GDestroyNotify) g_free);
		g_hash_table_insert (mgr->priv->domain_ipv4_nameservers,
				     g_strdup (domain),
				     servers);
	}
	g_hash_table_insert (servers,
			     GUINT_TO_POINTER (id),
			     g_strdup (server));
	if (!reload_named (mgr, error)) {
		g_hash_table_remove (servers, domain);
		return 0;
	}
	return id;
}

gboolean
nm_named_manager_remove_nameserver_ipv4 (NMNamedManager *mgr,
					 guint id,
					 GError **error)
{
	if (!g_hash_table_remove (mgr->priv->global_ipv4_nameservers,
				  GUINT_TO_POINTER (id)))
	{
		g_set_error (error,
			     NM_NAMED_MANAGER_ERROR,
			     NM_NAMED_MANAGER_ERROR_INVALID_ID,
			     "Invalid nameserver id");
		return FALSE;
	}

	if (!reload_named (mgr, error))
		return FALSE;
	
	return TRUE;
}

typedef struct {
	guint id;
	gboolean removed;
} NMNamedManagerRemoveData;

static void
remove_domain_id (gpointer key, gpointer value, gpointer data)
{
	const char *domain = key;
	GHashTable *servers = value;
	NMNamedManagerRemoveData *removedata = data;

	if (removedata->removed)
		return;
	
	if (g_hash_table_remove (servers, GUINT_TO_POINTER (removedata->id)))
		removedata->removed = TRUE;
}

gboolean
nm_named_manager_remove_domain_nameserver_ipv4 (NMNamedManager *mgr,
						guint id,
						GError **error)
{
	NMNamedManagerRemoveData data;
	
	data.id = id;
	data.removed = FALSE;

	g_hash_table_foreach (mgr->priv->domain_ipv4_nameservers,
			      remove_domain_id,
			      &data);
	if (!data.removed)
	{
		g_set_error (error,
			     NM_NAMED_MANAGER_ERROR,
			     NM_NAMED_MANAGER_ERROR_INVALID_ID,
			     "Invalid nameserver id");
		return FALSE;
	}

	if (!reload_named (mgr, error))
		return FALSE;
	
	return TRUE;
}

static int
safer_kill (const char *path, pid_t pid, int signum)
{
#ifdef __linux__
  {
    char buffer[1024];
    int len;
    char *procpath;
		
    procpath = g_strdup_printf ("/proc/%d/exe", pid); 
    len = readlink (procpath, buffer, sizeof (buffer)-1);
    g_free (procpath);
    buffer[len] = '\0';

	if (len > 0)
	{
		if (strcmp (path, buffer) != 0)
		{
			syslog (LOG_ERR, "pid %u with exe \"%s'\" did not match expected exe \"%s\"",
				(unsigned int) pid, buffer, path);
			errno = EPERM;
			return -1;
		}
	}	
  }
#endif
  return kill ((pid_t) pid, signum);
}
