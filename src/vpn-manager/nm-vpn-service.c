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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <glib.h>
#include <dbus/dbus.h>
#include "nm-dbus-vpn.h"
#include "nm-vpn-service.h"
#include "nm-utils.h"


struct NMVPNService
{
	int			 refcount;
	char			*name;
	char			*service;
	char			*program;
	NMVPNState	 state;
};


NMVPNService *nm_vpn_service_new (void)
{
	NMVPNService *service = g_malloc0 (sizeof (NMVPNService));

	service->refcount = 1;
	service->state = NM_VPN_STATE_SHUTDOWN;

	return service;
}

void nm_vpn_service_ref (NMVPNService *service)
{
	g_return_if_fail (service != NULL);

	service->refcount++;
}


void nm_vpn_service_unref (NMVPNService *service)
{
	g_return_if_fail (service != NULL);

	service->refcount--;
	if (service->refcount <= 0)
	{
		g_free (service->name);
		g_free (service->service);
		g_free (service->program);
		memset (service, 0, sizeof (NMVPNService));
		g_free (service);
	}
}


const char *nm_vpn_service_get_name (NMVPNService *service)
{
	g_return_val_if_fail (service != NULL, NULL);

	return service->name;
}


void nm_vpn_service_set_name (NMVPNService *service, const char *name)
{
	g_return_if_fail (service != NULL);

	if (service->name)
		g_free (service->name);
	service->name = g_strdup (name);
}


const char *nm_vpn_service_get_service_name (NMVPNService *service)
{
	g_return_val_if_fail (service != NULL, NULL);

	return service->service;
}


void nm_vpn_service_set_service_name (NMVPNService *service, const char *name)
{
	g_return_if_fail (service != NULL);

	if (service->service)
		g_free (service->service);
	service->service = g_strdup (name);
}


const char *nm_vpn_service_get_program (NMVPNService *service)
{
	g_return_val_if_fail (service != NULL, NULL);

	return service->program;
}


void nm_vpn_service_set_program (NMVPNService *service, const char *program)
{
	g_return_if_fail (service != NULL);

	if (service->program)
		g_free (service->program);
	service->program = g_strdup (program);
}


NMVPNState nm_vpn_service_get_state (NMVPNService *service)
{
	g_return_val_if_fail (service != NULL, NM_VPN_STATE_ERROR);

	return service->state;
}


void nm_vpn_service_set_state (NMVPNService *service, const NMVPNState state)
{
	g_return_if_fail (service != NULL);

	service->state = state;
}


gboolean nm_vpn_service_exec_daemon (NMVPNService *service)
{
	GPtrArray		*vpn_argv;
	GError		*error = NULL;
	GPid			 pid;

	g_return_val_if_fail (service != NULL, FALSE);

	if (!nm_vpn_service_get_program (service))
		return FALSE;

	vpn_argv = g_ptr_array_new ();
	g_ptr_array_add (vpn_argv, (char *) nm_vpn_service_get_program (service));
	g_ptr_array_add (vpn_argv, NULL);

	if (!g_spawn_async (NULL, (char **) vpn_argv->pdata, NULL, 0, NULL, NULL, &pid, &error))
	{
		g_ptr_array_free (vpn_argv, TRUE);
		nm_warning ("Could not activate the VPN service '%s'.  error: '%s'.", nm_vpn_service_get_service_name (service), error->message);
		g_error_free (error);
		return FALSE;
	}
	g_ptr_array_free (vpn_argv, TRUE);
	nm_info ("Activated the VPN service '%s' with PID %d.", nm_vpn_service_get_service_name (service), pid);

	/* Wait a bit for the daemon to start up */
	/* FIXME: don't sleep, keep retrying dbus message or something */
	sleep (1);

	return TRUE;
}

