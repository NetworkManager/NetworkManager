/* nmcli - command-line tool to control NetworkManager
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
 * (C) Copyright 2010 Red Hat, Inc.
 */

#ifndef NMC_NMCLI_H
#define NMC_NMCLI_H

#include <nm-remote-settings.h>
#include <nm-remote-settings-system.h>


/* nmcli exit codes */
typedef enum {
	/* Indicates successful execution */
	NMC_RESULT_SUCCESS = 0,

	/* Unknown / unspecified error */
	NMC_RESULT_ERROR_UNKNOWN,

	/* A timeout expired */
	NMC_RESULT_ERROR_TIMEOUT_EXPIRED,

	/* Error in connection activation */
	NMC_RESULT_ERROR_CON_ACTIVATION,

	/* Error in connection deactivation */
	NMC_RESULT_ERROR_CON_DEACTIVATION,

	/* Error in device disconnect */
	NMC_RESULT_ERROR_DEV_DISCONNECT
} NMCResultCode;

typedef enum {
	NMC_PRINT_TERSE = 0,
	NMC_PRINT_NORMAL,
	NMC_PRINT_PRETTY
} NMCPrintOutput;

/* NmCli - main structure */
typedef struct _NmCli {
	NMClient *client;
	NMClient *(*get_client) (struct _NmCli *nmc);

	NMCResultCode return_value;
	GString *return_text;

	int timeout;

	NMRemoteSettingsSystem *system_settings;
	NMRemoteSettings *user_settings;

	gboolean system_settings_running;
	gboolean user_settings_running;

	GSList *system_connections;
	GSList *user_connections;

	gboolean should_wait;
	NMCPrintOutput print_output;
} NmCli;

#endif /* NMC_NMCLI_H */
