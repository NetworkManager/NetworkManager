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
 * (C) Copyright 2010 - 2012 Red Hat, Inc.
 */

#ifndef NMC_NMCLI_H
#define NMC_NMCLI_H

#include <glib.h>

#include <nm-client.h>
#include <nm-remote-settings.h>

/* nmcli exit codes */
typedef enum {
	/* Indicates successful execution */
	NMC_RESULT_SUCCESS = 0,

	/* Unknown / unspecified error */
	NMC_RESULT_ERROR_UNKNOWN = 1,

	/* Wrong invocation of nmcli */
	NMC_RESULT_ERROR_USER_INPUT = 2,

	/* A timeout expired */
	NMC_RESULT_ERROR_TIMEOUT_EXPIRED = 3,

	/* Error in connection activation */
	NMC_RESULT_ERROR_CON_ACTIVATION = 4,

	/* Error in connection deactivation */
	NMC_RESULT_ERROR_CON_DEACTIVATION = 5,

	/* Error in device disconnect */
	NMC_RESULT_ERROR_DEV_DISCONNECT = 6,

	/* Error in connection deletion */
	NMC_RESULT_ERROR_CON_DEL = 7,

	/* NetworkManager is not running */
	NMC_RESULT_ERROR_NM_NOT_RUNNING = 8,

	/* nmcli and NetworkManager versions mismatch */
	NMC_RESULT_ERROR_VERSIONS_MISMATCH = 9,

	/* Connection/Device/AP not found */
	NMC_RESULT_ERROR_NOT_FOUND = 10
} NMCResultCode;

typedef enum {
	NMC_PRINT_TERSE = 0,
	NMC_PRINT_NORMAL = 1,
	NMC_PRINT_PRETTY = 2
} NMCPrintOutput;

/* === Output fields === */
/* Flags for NmcOutputField */
#define NMC_OF_FLAG_FIELD_NAMES        0x00000001   /* Print field names instead of values */
#define NMC_OF_FLAG_SECTION_PREFIX     0x00000002   /* Use the first value as section prefix for the other field names - just in multiline */
#define NMC_OF_FLAG_MAIN_HEADER_ADD    0x00000004   /* Print main header in addition to values/field names */
#define NMC_OF_FLAG_MAIN_HEADER_ONLY   0x00000008   /* Print main header only */

typedef struct _NmcOutputField {
	const char *name;               /* Field's name */
	const char *name_l10n;          /* Field's name for translation */
	int width;                      /* Width in screen columns */
	struct _NmcOutputField *group;  /* Points to an array with available section field names if this is a section (group) field */
	void *value;                    /* Value of current field - char* or char** (NULL-terminated array) */
	gboolean value_is_array;        /* Whether value is char** instead of char* */
	gboolean free_value;            /* Whether to free the value */
	guint32 flags;                  /* Flags - whether and how to print values/field names/headers */
} NmcOutputField;

typedef struct {
	GArray *indices;      /* Array of field indices to the array of allowed fields */
	char *header_name;    /* Name of the output */
	int indent;           /* Indent by this number of spaces */
} NmcPrintFields;

typedef enum {
	NMC_TERM_COLOR_NORMAL  = 0,
	NMC_TERM_COLOR_BLACK   = 1,
	NMC_TERM_COLOR_RED     = 2,
	NMC_TERM_COLOR_GREEN   = 3,
	NMC_TERM_COLOR_YELLOW  = 4,
	NMC_TERM_COLOR_BLUE    = 5,
	NMC_TERM_COLOR_MAGENTA = 6,
	NMC_TERM_COLOR_CYAN    = 7,
	NMC_TERM_COLOR_WHITE   = 8
} NmcTermColor;

/* NmCli - main structure */
typedef struct _NmCli {
	NMClient *client;                                 /* Pointer to NMClient of libnm-glib */
	NMClient *(*get_client) (struct _NmCli *nmc);     /* Pointer to function for creating NMClient */

	NMCResultCode return_value;                       /* Return code of nmcli */
	GString *return_text;                             /* Reason text */

	int timeout;                                      /* Operation timeout */

	NMRemoteSettings *system_settings;                /* System settings */
	gboolean system_settings_running;                 /* Is system settings service running? */
	GSList *system_connections;                       /* List of system connections */

	gboolean should_wait;                             /* Indication that nmcli should not end yet */
	gboolean nowait_flag;                             /* '--nowait' option; used for passing to callbacks */
	NMCPrintOutput print_output;                      /* Output mode */
	gboolean multiline_output;                        /* Multiline output instead of default tabular */
	gboolean mode_specified;                          /* Whether tabular/multiline mode was specified via '--mode' option */
	gboolean escape_values;                           /* Whether to escape ':' and '\' in terse tabular mode */
	char *required_fields;                            /* Required fields in output: '--fields' option */
	GPtrArray *output_data;                           /* GPtrArray of arrays of NmcOutputField structs - accumulates data for output */
	NmcPrintFields print_fields;                      /* Structure with field indices to print */
	gboolean nocheck_ver;                             /* Don't check nmcli and NM versions: option '--nocheck' */
	gboolean ask;                                     /* Ask for missing parameters: option '--ask' */
	gboolean editor_status_line;                      /* Whether to display status line in connection editor */
	gboolean editor_save_confirmation;                /* Whether to ask for confirmation on saving connections with 'autoconnect=yes' */
	NmcTermColor editor_prompt_color;                 /* Color of prompt in connection editor */
} NmCli;

/* Error quark for GError domain */
#define NMCLI_ERROR (nmcli_error_quark ())
GQuark nmcli_error_quark (void);

#endif /* NMC_NMCLI_H */
