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
 * Copyright (C) 2016 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-ppp-manager-call.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "nm-manager.h"
#include "nm-core-utils.h"
#include "nm-ppp-plugin-api.h"

#define PPP_PLUGIN_PATH NMPLUGINDIR "/libnm-ppp-plugin.so"

/*****************************************************************************/

static NMPPPOps *ppp_ops = NULL;

NMPPPManager *
nm_ppp_manager_create (const char *iface, GError **error)
{
	NMPPPManager *ret;
	GModule *plugin;
	GError *error_local = NULL;
	NMPPPOps *ops;
	struct stat st;
	int errsv;

	if (G_UNLIKELY (!ppp_ops)) {
		if (stat (PPP_PLUGIN_PATH, &st) != 0) {
			errsv = errno;
			g_set_error_literal (error,
			                     NM_MANAGER_ERROR, NM_MANAGER_ERROR_MISSING_PLUGIN,
			                     "the PPP plugin " PPP_PLUGIN_PATH " is not installed");
			return NULL;
		}

		if (!nm_utils_validate_plugin (PPP_PLUGIN_PATH, &st, &error_local)) {
			g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_MISSING_PLUGIN,
			             "could not load the PPP plugin " PPP_PLUGIN_PATH ": %s",
			             error_local->message);
			g_clear_error (&error_local);
			return NULL;
		}

		plugin = g_module_open (PPP_PLUGIN_PATH, G_MODULE_BIND_LOCAL);
		if (!plugin) {
			g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_MISSING_PLUGIN,
			             "could not load the PPP plugin " PPP_PLUGIN_PATH ": %s",
			             g_module_error ());
			return NULL;
		}

		if (!g_module_symbol (plugin, "ppp_ops", (gpointer) &ops)) {
			g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_MISSING_PLUGIN,
			             "error loading the PPP plugin: %s", g_module_error ());
			return NULL;
		}

		/* after loading glib types from the plugin, we cannot unload the library anymore.
		 * Make it resident. */
		g_module_make_resident (plugin);

		nm_assert (ops);
		nm_assert (ops->create);
		nm_assert (ops->start);
		nm_assert (ops->stop_async);
		nm_assert (ops->stop_finish);
		nm_assert (ops->stop_sync);

		ppp_ops = ops;

		nm_log_info (LOGD_CORE | LOGD_PPP, "loaded PPP plugin " PPP_PLUGIN_PATH);
	}

	ret = ppp_ops->create (iface);
	g_return_val_if_fail (ret, NULL);
	return ret;
}

void
nm_ppp_manager_set_route_parameters (NMPPPManager *self,
                                     guint32 ip4_route_table,
                                     guint32 ip4_route_metric,
                                     guint32 ip6_route_table,
                                     guint32 ip6_route_metric)
{
	g_return_if_fail (ppp_ops);

	ppp_ops->set_route_parameters (self,
	                               ip4_route_table,
	                               ip4_route_metric,
	                               ip6_route_table,
	                               ip6_route_metric);
}

gboolean
nm_ppp_manager_start (NMPPPManager *self,
                      NMActRequest *req,
                      const char *ppp_name,
                      guint32 timeout_secs,
                      guint baud_override,
                      GError **err)
{
	g_return_val_if_fail (ppp_ops, FALSE);

	return ppp_ops->start (self, req, ppp_name, timeout_secs, baud_override, err);
}

void
nm_ppp_manager_stop_async (NMPPPManager *self,
                           GCancellable *cancellable,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
	g_return_if_fail (ppp_ops);

	ppp_ops->stop_async (self, cancellable, callback, user_data);
}

gboolean
nm_ppp_manager_stop_finish (NMPPPManager *self,
                            GAsyncResult *res,
                            GError **error)
{
	g_return_val_if_fail (ppp_ops, FALSE);

	return ppp_ops->stop_finish (self, res, error);
}

void
nm_ppp_manager_stop_sync (NMPPPManager *self)
{
	g_return_if_fail (ppp_ops);

	ppp_ops->stop_sync (self);
}

