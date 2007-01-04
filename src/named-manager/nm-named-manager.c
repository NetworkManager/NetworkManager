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
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <resolv.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <glib.h>
#include <dbus/dbus.h>

#include "nm-ip4-config.h"
#include "nm-utils.h"
#include "NetworkManagerSystem.h"
#include "nm-dbus-manager.h"

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#ifndef RESOLV_CONF
#define RESOLV_CONF "/etc/resolv.conf"
#endif

#ifndef NAMED_DBUS_SERVICE
#define NAMED_DBUS_SERVICE "com.redhat.named"
#define NAMED_DBUS_INTERFACE "com.redhat.named"
#define NAMED_DBUS_PATH "/com/redhat/named"
#endif

G_DEFINE_TYPE(NMNamedManager, nm_named_manager, G_TYPE_OBJECT)

#define NM_NAMED_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                         NM_TYPE_NAMED_MANAGER, \
                                         NMNamedManagerPrivate))

static NMIP4Config *get_last_default_domain (NMNamedManager *mgr);

static gboolean add_all_ip4_configs_to_named (NMNamedManager *mgr);

static gboolean rewrite_resolv_conf (NMNamedManager *mgr, NMIP4Config *config, GError **error);

static gboolean remove_ip4_config_from_named (NMNamedManager *mgr, NMIP4Config *config);


struct NMNamedManagerPrivate {
	gboolean		use_named;
	NMDBusManager *	dbus_mgr;
	GSList *		configs;

	gboolean disposed;
};


GQuark
nm_named_manager_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm_named_manager_error");

	return quark;
}


/*
 * nm_named_manager_process_name_owner_changed
 *
 * Respond to "service created"/"service deleted" signals from dbus for named.
 *
 */
static void
nm_named_manager_name_owner_changed (NMDBusManager *dbus_mgr,
                                     DBusConnection *connection,
                                     const char *name,
                                     const char *old,
                                     const char *new,
                                     gpointer user_data)
{
	NMNamedManager *mgr = (NMNamedManager *) user_data;
	gboolean	handled = FALSE;
	gboolean	old_owner_good = (old && strlen (old));
	gboolean	new_owner_good = (new && strlen (new));

	g_return_if_fail (mgr != NULL);
	g_return_if_fail (name != NULL);

	/* Ensure signal is for named's service */
	if (strcmp (NAMED_DBUS_SERVICE, name) != 0)
		return;

	if (!old_owner_good && new_owner_good) {
		mgr->priv->use_named = TRUE;

		if (!add_all_ip4_configs_to_named (mgr))
			nm_warning ("Could not set fowarders in named.");

		handled = TRUE;
	} else if (old_owner_good && !new_owner_good) {
		mgr->priv->use_named = FALSE;
		handled = TRUE;
	}

	if (handled) {
		GError *error = NULL;
		if (!rewrite_resolv_conf (mgr, get_last_default_domain (mgr), &error)) {
			nm_warning ("Could not write resolv.conf.  Error: '%s'",
			            error ? error->message : "(none)");
			g_error_free (error);
		}
	}
}

static void
nm_named_manager_dbus_connection_changed (NMDBusManager *dbus_mgr,
                                          DBusConnection *dbus_connection,
                                          gpointer user_data)
{
	NMNamedManager *mgr = (NMNamedManager *) user_data;
	gboolean handled = FALSE;

	g_return_if_fail (mgr != NULL);

	if (dbus_connection) {
		if (nm_dbus_manager_name_has_owner (dbus_mgr, NAMED_DBUS_SERVICE)) {
			mgr->priv->use_named = TRUE;
			if (!add_all_ip4_configs_to_named (mgr))
				nm_warning ("Could not set fowarders in named.");
			handled = TRUE;
		}
	} else {
		mgr->priv->use_named = FALSE;
		handled = TRUE;
	}

	if (handled) {
		GError *error = NULL;
		if (!rewrite_resolv_conf (mgr, get_last_default_domain (mgr), &error)) {
			nm_warning ("Could not write resolv.conf.  Error: '%s'",
			            error ? error->message : "(none)");
			g_error_free (error);
		}
	}
}

static char *
compute_nameservers (NMNamedManager *mgr, NMIP4Config *config)
{
	int i, num_nameservers;
	GString *str = NULL;

	g_return_val_if_fail (mgr != NULL, g_strdup (""));
	g_return_val_if_fail (config != NULL, g_strdup (""));

	num_nameservers = nm_ip4_config_get_num_nameservers (config);
	if (num_nameservers > 3)
		num_nameservers = 3; /* 'man resolv.conf' says we can't have > 3 */
	for (i = 0; i < num_nameservers; i++)
	{
		#define ADDR_BUF_LEN 50
		struct in_addr addr;
		char *buf;

		if (!str)
			str = g_string_new ("");

		addr.s_addr = nm_ip4_config_get_nameserver (config, i);
		buf = g_malloc0 (ADDR_BUF_LEN);
		inet_ntop (AF_INET, &addr, buf, ADDR_BUF_LEN);

		g_string_append (str, "nameserver ");
		g_string_append (str, buf);
		g_string_append_c (str, '\n');
		g_free (buf);
	}

	if (!str)
		return g_strdup ("");

	return g_string_free (str, FALSE);
}

static char *
compute_searches (NMNamedManager *mgr, NMIP4Config *config)
{
	int i, num_searches;
	GString *str = NULL;

	g_return_val_if_fail (mgr != NULL, g_strdup (""));

	/* config can be NULL */
	if (!config)
		return g_strdup ("");

	num_searches = nm_ip4_config_get_num_domains (config);
	for (i = 0; i < num_searches; i++)
	{
		if (!str)
			str = g_string_new ("search");

		g_string_append_c (str, ' ');
		g_string_append (str, nm_ip4_config_get_domain (config, i));		
	}

	if (!str)
		return g_strdup ("");
	else
		g_string_append_c (str, '\n');

	return g_string_free (str, FALSE);
}

static gboolean
rewrite_resolv_conf (NMNamedManager *mgr, NMIP4Config *config, GError **error)
{
	const char *	tmp_resolv_conf = RESOLV_CONF ".tmp";
	char *		searches = NULL;
	FILE *		f;

	/* If no config, we don't have anything to update, so exit silently */
	if (!config)
		return TRUE;

	/* If the sysadmin disabled modifying resolv.conf, exit silently */
	if (!nm_system_should_modify_resolv_conf ())
	{
		nm_info ("DHCP returned name servers but system has disabled dynamic modification!");
		return TRUE;
	}

	if ((f = fopen (tmp_resolv_conf, "w")) == NULL)
		goto lose;

	if (fprintf (f, "%s","# generated by NetworkManager, do not edit!\n\n") < 0)
		goto lose;

	searches = compute_searches (mgr, config);

	if (mgr->priv->use_named == TRUE)
	{
		/* Using caching-nameserver & local DNS */
		if (fprintf (f, "%s%s%s", "; Use a local caching nameserver controlled by NetworkManager\n\n", searches, "\nnameserver 127.0.0.1\n") < 0)
			goto lose;
	}
	else
	{
		/* Using glibc resolver */
		char *nameservers = compute_nameservers (mgr, config);

		fprintf (f, "%s\n\n", searches);
		g_free (searches);

		fprintf (f, "%s\n\n", nameservers);
		g_free (nameservers);
	}

	if (fclose (f) < 0)
		goto lose;

	if (rename (tmp_resolv_conf, RESOLV_CONF) < 0)
		goto lose;
	nm_system_update_dns ();
	return TRUE;

lose:
	g_free (searches);
	fclose (f);
	g_set_error (error,
		     NM_NAMED_MANAGER_ERROR,
		     NM_NAMED_MANAGER_ERROR_SYSTEM,
		     "Could not update " RESOLV_CONF ": %s\n", g_strerror (errno));
	return FALSE;
}

static const char *
get_domain_for_config (NMIP4Config *config, gboolean *dflt)
{
	gboolean is_dflt = FALSE;
	const char *domain;

	g_return_val_if_fail (config != NULL, NULL);

	/* Primary configs always use default domain */
	if (!nm_ip4_config_get_secondary (config))
		is_dflt = TRUE;
	/* Any config without a domain becomes default */
	if (nm_ip4_config_get_num_domains (config) == 0)
		is_dflt = TRUE;

	if (is_dflt)
		domain = ".";	/* Default domain */
	else
		domain = nm_ip4_config_get_domain (config, 0);

	if (dflt)
		*dflt = is_dflt;

	return domain;
}

static gboolean
add_ip4_config_to_named (NMNamedManager *mgr, NMIP4Config *config)
{
	const char *domain;
	int i, num_nameservers;
	gboolean		success = FALSE;
	DBusMessage *	message;
	DBusMessage *	reply = NULL;
	DBusError		error;
	gboolean		dflt = FALSE;
	DBusConnection *dbus_connection;

	g_return_val_if_fail (mgr != NULL, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	dbus_error_init (&error);

	dbus_connection = nm_dbus_manager_get_dbus_connection (mgr->priv->dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get dbus connection.");
		goto out;
	}

	if (!(domain = get_domain_for_config (config, &dflt)))
		goto out;

	message = dbus_message_new_method_call (NAMED_DBUS_SERVICE,
	                                        NAMED_DBUS_PATH,
	                                        NAMED_DBUS_INTERFACE,
	                                        "SetForwarders");
	if (!message) {
		nm_warning ("could not allocate dbus message.");
		goto out;
	}

	dbus_message_append_args (message,
	                          DBUS_TYPE_STRING, &domain,
	                          DBUS_TYPE_INVALID);

	num_nameservers = nm_ip4_config_get_num_nameservers (config);
	for (i = 0; i < num_nameservers; i++) {
		dbus_uint32_t	server = nm_ip4_config_get_nameserver (config, i);
		dbus_uint16_t	port = htons (53); /* default DNS port */
		char			fwd_policy = dflt ? 1 : 2; /* 'first' : 'only' */

		dbus_message_append_args (message,
		                          DBUS_TYPE_UINT32, &server,
		                          DBUS_TYPE_UINT16, &port,
		                          DBUS_TYPE_BYTE, &fwd_policy,
		                          DBUS_TYPE_INVALID);
	}

	reply = dbus_connection_send_with_reply_and_block (dbus_connection,
	                                                   message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error)) {
		nm_warning ("Could not set forwarders for zone '%s'.  Error: '%s'.",
		            domain,
		            error.message);
		goto out;
	}

	if (!reply) {
		nm_warning ("Could not set forwarders for zone '%s', did not receive "
		            "a reply from named.",
		            domain);
		goto out;
	}

	if (dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_ERROR) {
		const char *err_msg = NULL;
		dbus_message_get_args (reply,
		                       NULL,
		                       DBUS_TYPE_STRING, &err_msg,
		                       DBUS_TYPE_INVALID);
		nm_warning ("Could not set forwarders for zone '%s'. "
		            "Named replied: '%s'",
		            domain,
		            err_msg);		
	}
	success = TRUE;

out:
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	dbus_message_unref (reply);
	return success;
}

static gboolean
add_all_ip4_configs_to_named (NMNamedManager *mgr)
{
	GSList *elt = NULL;

	g_return_val_if_fail (mgr != NULL, FALSE);

	for (elt = mgr->priv->configs; elt; elt = g_slist_next (elt))
		add_ip4_config_to_named (mgr, (NMIP4Config *)(elt->data));
		
	return TRUE;
}

static gboolean
remove_one_zone_from_named (NMNamedManager *mgr, const char *zone)
{
	gboolean		success = FALSE;
	DBusMessage *	message = NULL;
	DBusMessage *	reply = NULL;
	DBusError		error;
	DBusConnection *dbus_connection;

	g_return_val_if_fail (mgr != NULL, FALSE);
	g_return_val_if_fail (zone != NULL, FALSE);

	dbus_error_init (&error);

	dbus_connection = nm_dbus_manager_get_dbus_connection (mgr->priv->dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get dbus connection.");
		goto out;
	}

	message = dbus_message_new_method_call (NAMED_DBUS_SERVICE,
	                                        NAMED_DBUS_PATH,
	                                        NAMED_DBUS_INTERFACE,
	                                        "SetForwarders");
	if (!message) {
		nm_warning ("could not allocate dbus message.");
		goto out;
	}

	dbus_message_append_args (message,
	                          DBUS_TYPE_STRING, &zone,
	                          DBUS_TYPE_INVALID);

	reply = dbus_connection_send_with_reply_and_block (dbus_connection,
	                                                   message,
	                                                   -1,
	                                                   &error);
	dbus_message_unref (message);

	if (dbus_error_is_set (&error)) {
		nm_warning ("Could not remove forwarders for zone '%s'.  "
		            "Error: '%s'.",
		            zone,
		            error.message);
		goto out;
	}

	if (!reply) {
		nm_warning ("Could not remove forwarders for zone '%s', did not "
		            " receive a reply from named.",
		            zone);
		goto out;
	}

	if (dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_ERROR) {
		const char *err_msg = NULL;
		dbus_message_get_args (reply,
		                       NULL,
		                       DBUS_TYPE_STRING, &err_msg,
		                       DBUS_TYPE_INVALID);
		nm_warning ("Could not remove forwarders for zone '%s'.  "
		            "Named replied: '%s'",
		            zone,
		            err_msg);
		goto out;
	}
	success = TRUE;

out:
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	dbus_message_unref (reply);
	return success;
}

static gboolean
remove_ip4_config_from_named (NMNamedManager *mgr, NMIP4Config *config)
{
	const char *domain;

	g_return_val_if_fail (mgr != NULL, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	if (!(domain = get_domain_for_config (config, NULL)))
		return FALSE;

	return remove_one_zone_from_named (mgr, domain);
}

static void
remove_all_zones_from_named (NMNamedManager *mgr)
{
	DBusMessage *		message;
	DBusMessage *		reply = NULL;
	DBusError			error;
	DBusMessageIter	iter;
	GSList *			zones = NULL;
	GSList *			elt = NULL;
	DBusConnection *	dbus_connection;

	g_return_if_fail (mgr != NULL);

	if (!mgr->priv->use_named)
		return;

	dbus_connection = nm_dbus_manager_get_dbus_connection (mgr->priv->dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get dbus connection.");
		goto out;
	}

	message = dbus_message_new_method_call (NAMED_DBUS_SERVICE,
	                                        NAMED_DBUS_PATH,
	                                        NAMED_DBUS_INTERFACE,
	                                        "GetForwarders");
	if (!message) {
		nm_warning ("could not allocate dbus message.");
		goto out;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (dbus_connection,
	                                                   message,
	                                                   -1,
	                                                   &error);
	dbus_message_unref (message);

	if (dbus_error_is_set (&error)) {
		nm_warning ("Could not get forwarder list from named.  Error: '%s'.",
		            error.message);
		goto out;
	}

	if (!reply) {
		nm_warning ("Could not get forarder list from named, did not receive "
		            " a reply from named.");
		goto out;
	}

	if (dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_ERROR) {
		const char *err_msg = NULL;
		dbus_message_get_args (reply,
		                       NULL,
		                       DBUS_TYPE_STRING, &err_msg,
		                       DBUS_TYPE_INVALID);
		nm_warning ("Could not get forwarder list from named.  "
		            "Named replied: '%s'",
		            err_msg);
		goto out;
	}

	dbus_message_iter_init (reply, &iter);
	do {
		/* We depend on zones being the only strings in what 
		 * named returns (obviously)
		 */
		if (dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_STRING) {
			char *zone = NULL;
			dbus_message_iter_get_basic (&iter, &zone);
			zones = g_slist_append (zones, g_strdup (zone));
		}
	} while (dbus_message_iter_next (&iter));

	/* Remove all the zones from named */
	for (elt = zones; elt; elt = g_slist_next (elt))
		remove_one_zone_from_named (mgr, (const char *)(elt->data));
	
	g_slist_foreach (zones, (GFunc) g_free, NULL);
	g_slist_free (zones);

out:
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	dbus_message_unref (reply);
}

gboolean
nm_named_manager_add_ip4_config (NMNamedManager *mgr, NMIP4Config *config)
{
	GError *	error = NULL;

	g_return_val_if_fail (mgr != NULL, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	/* Don't allow the same zone added twice */
	if (g_slist_find (mgr->priv->configs, config))
		return FALSE;

	/* First clear out and reload configs in named */
	if (mgr->priv->use_named)
	{
		remove_all_zones_from_named (mgr);
		add_all_ip4_configs_to_named (mgr);
	}

	nm_ip4_config_ref (config);
	mgr->priv->configs = g_slist_append (mgr->priv->configs, config);

	/* Activate the zone config */
	if (mgr->priv->use_named)
		add_ip4_config_to_named (mgr, config);

	if (!rewrite_resolv_conf (mgr, config, &error))
	{
		nm_warning ("Could not commit DNS changes.  Error: '%s'", error ? error->message : "(none)");
		g_error_free (error);
	}

	return TRUE;
}

static NMIP4Config *
get_last_default_domain (NMNamedManager *mgr)
{
	GSList *elt = NULL;
	NMIP4Config *last_default = NULL;
	NMIP4Config *last = NULL;

	for (elt = mgr->priv->configs; elt; elt = g_slist_next (elt))
	{
		gboolean dflt = FALSE;
		const char *domain = NULL;
		NMIP4Config *config = (NMIP4Config *)(elt->data);

		last = config;
		domain = get_domain_for_config (config, &dflt);
		if (dflt)
			last_default = config;
	}

	/* Fall back the last config added to the list if none are the default */
	return (last_default ? last_default : last);
}

gboolean
nm_named_manager_remove_ip4_config (NMNamedManager *mgr, NMIP4Config *config)
{
	GError *	error = NULL;

	g_return_val_if_fail (mgr != NULL, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	/* Can't remove it if it wasn't in the list to begin with */
	if (!g_slist_find (mgr->priv->configs, config))
		return FALSE;

	/* Deactivate the config */
	if (mgr->priv->use_named)
		remove_ip4_config_from_named (mgr, config);

	mgr->priv->configs = g_slist_remove (mgr->priv->configs, config);
	nm_ip4_config_unref (config);	

	/* Clear out and reload configs since we may need a new
	 * default zone if the one we are removing was the old
	 * default zone.
	 */
	if (mgr->priv->use_named)
	{
		remove_all_zones_from_named (mgr);
		add_all_ip4_configs_to_named (mgr);
	}

	if (!rewrite_resolv_conf (mgr, get_last_default_domain (mgr), &error))
	{
		nm_warning ("Could not commit DNS changes.  Error: '%s'", error ? error->message : "(none)");
		if (error)
			g_error_free (error);
	}

	return TRUE;
}


static void
nm_named_manager_init (NMNamedManager *mgr)
{
	mgr->priv = NM_NAMED_MANAGER_GET_PRIVATE (mgr);
	mgr->priv->use_named = FALSE;
	mgr->priv->dbus_mgr = nm_dbus_manager_get ();
	g_signal_connect (G_OBJECT (mgr->priv->dbus_mgr),
	                  "name-owner-changed",
	                  G_CALLBACK (nm_named_manager_name_owner_changed),
	                  mgr);
	g_signal_connect (G_OBJECT (mgr->priv->dbus_mgr),
	                  "dbus-connection-changed",
	                  G_CALLBACK (nm_named_manager_dbus_connection_changed),
	                  mgr);
}

static void
nm_named_manager_dispose (GObject *object)
{
	NMNamedManager *mgr = NM_NAMED_MANAGER (object);
	GSList *elt;

	if (mgr->priv->disposed)
		return;
	mgr->priv->disposed = TRUE;

	for (elt = mgr->priv->configs; elt; elt = g_slist_next (elt))
		remove_ip4_config_from_named (mgr, (NMIP4Config *)(elt->data));
}

static void
nm_named_manager_finalize (GObject *object)
{
	NMNamedManager *mgr = NM_NAMED_MANAGER (object);

	g_return_if_fail (mgr->priv != NULL);

	g_slist_foreach (mgr->priv->configs, (GFunc) nm_ip4_config_unref, NULL);
	g_slist_free (mgr->priv->configs);

	g_object_unref (mgr->priv->dbus_mgr);

	G_OBJECT_CLASS (nm_named_manager_parent_class)->finalize (object);
}

NMNamedManager *
nm_named_manager_new (void)
{
	return NM_NAMED_MANAGER (g_object_new (NM_TYPE_NAMED_MANAGER, NULL));
}

static void
nm_named_manager_class_init (NMNamedManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = nm_named_manager_dispose;
	object_class->finalize = nm_named_manager_finalize;

	g_type_class_add_private (object_class, sizeof (NMNamedManagerPrivate));
}

