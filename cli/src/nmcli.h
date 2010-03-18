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

#include <glib.h>

#include <nm-client.h>
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

/* === Output fields === */
typedef struct {
	const char *name;       /* Field's name */
	const char *name_l10n;  /* Field's name for translation */
	int width;              /* Width in screen columns */
	const char *value;      /* Value of current field */
	guint32 flags;          /* Flags */
} NmcOutputField;

/* Flags for NmcPrintFields */
#define	NMC_PF_FLAG_MULTILINE    0x00000001   /* Multiline output instead of tabular*/
#define	NMC_PF_FLAG_TERSE        0x00000002   /* Terse outpud mode */
#define	NMC_PF_FLAG_PRETTY       0x00000004   /* Pretty output mode */
#define	NMC_PF_FLAG_HEADER       0x00000008   /* Print headers instead of values */
#define	NMC_PF_FLAG_ESCAPE       0x00000010   /* Escape column separator and '\' */

typedef struct {
	GArray *indices;      /* Array of field indices to the array of allowed fields */
	char *header_name;    /* Name of the output */
	int indent;           /* Indent by this number of spaces */
	guint32 flags;        /* Various flags for controlling output: see NMC_PF_FLAG_* values */
} NmcPrintFields;

/* NmCli - main structure */
typedef struct _NmCli {
	NMClient *client;                                 /* Pointer to NMClient of libnm-glib */
	NMClient *(*get_client) (struct _NmCli *nmc);     /* Pointer to function for creating NMClient */

	NMCResultCode return_value;                       /* Return code of nmcli */
	GString *return_text;                             /* Reason text */

	int timeout;                                      /* Operation timeout */

	NMRemoteSettingsSystem *system_settings;          /* System settings */
	NMRemoteSettings *user_settings;                  /* User settings */

	gboolean system_settings_running;                 /* Is system settings service running? */
	gboolean user_settings_running;                   /* Is user settings service running? */

	GSList *system_connections;                       /* List of system connections */
	GSList *user_connections;                         /* List of user connections */

	gboolean should_wait;                             /* Indication that nmcli should not end yet */
	NMCPrintOutput print_output;                      /* Output mode */
	gboolean multiline_output;                        /* Multiline output instead of default tabular */
	gboolean escape_values;                           /* Whether to escape ':' and '\' in terse tabular mode */
	char *required_fields;                            /* Required fields in output: '--fields' option */
	NmcOutputField *allowed_fields;                   /* Array of allowed fields for particular commands */
	NmcPrintFields print_fields;                      /* Structure with field indices to print */
} NmCli;

#endif /* NMC_NMCLI_H */
