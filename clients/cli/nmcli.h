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
 * Copyright 2010 - 2018 Red Hat, Inc.
 */

#ifndef NMC_NMCLI_H
#define NMC_NMCLI_H

#include "nm-secret-agent-simple.h"
#include "nm-meta-setting-desc.h"

struct _NMPolkitListener;

typedef char *(*NmcCompEntryFunc) (const char *, int);

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

	/* No more used, keep to preserve API */
	NMC_RESULT_ERROR_VERSIONS_MISMATCH = 9,

	/* Connection/Device/AP not found */
	NMC_RESULT_ERROR_NOT_FOUND = 10,

	/* --complete-args signals a file name may follow */
	NMC_RESULT_COMPLETE_FILE = 65,
} NMCResultCode;

typedef enum {
	NMC_PRINT_TERSE = 0,
	NMC_PRINT_NORMAL = 1,
	NMC_PRINT_PRETTY = 2
} NMCPrintOutput;

static inline NMMetaAccessorGetType
nmc_print_output_to_accessor_get_type (NMCPrintOutput print_output)
{
	return   NM_IN_SET (print_output, NMC_PRINT_NORMAL, NMC_PRINT_PRETTY)
	       ? NM_META_ACCESSOR_GET_TYPE_PRETTY
	       : NM_META_ACCESSOR_GET_TYPE_PARSABLE;
}

/* === Output fields === */

typedef enum {
	NMC_OF_FLAG_FIELD_NAMES        = 0x00000001,   /* Print field names instead of values */
	NMC_OF_FLAG_SECTION_PREFIX     = 0x00000002,   /* Use the first value as section prefix for the other field names - just in multiline */
	NMC_OF_FLAG_MAIN_HEADER_ADD    = 0x00000004,   /* Print main header in addition to values/field names */
	NMC_OF_FLAG_MAIN_HEADER_ONLY   = 0x00000008,   /* Print main header only */
} NmcOfFlags;

extern const NMMetaType nmc_meta_type_generic_info;

typedef struct _NmcOutputField NmcOutputField;
typedef struct _NmcMetaGenericInfo NmcMetaGenericInfo;

struct _NmcOutputField {
	const NMMetaAbstractInfo *info;
	int width;                      /* Width in screen columns */
	void *value;                    /* Value of current field - char* or char** (NULL-terminated array) */
	gboolean value_is_array;        /* Whether value is char** instead of char* */
	gboolean free_value;            /* Whether to free the value */
	NmcOfFlags flags;               /* Flags - whether and how to print values/field names/headers */
	NMMetaColor color;              /* Use this color to print value */
};

typedef struct _NmcConfig {
	NMCPrintOutput print_output;                      /* Output mode */
	bool use_colors;                                  /* Whether to use colors for output: option '--color' */
	bool multiline_output;                            /* Multiline output instead of default tabular */
	bool escape_values;                               /* Whether to escape ':' and '\' in terse tabular mode */
	bool in_editor;                                   /* Whether running the editor - nmcli con edit' */
	bool show_secrets;                                /* Whether to display secrets (both input and output): option '--show-secrets' */
	bool overview;                                    /* Overview mode (hide default values) */
	const char *palette[_NM_META_COLOR_NUM];          /* Color palette */
} NmcConfig;

typedef struct _NmcOutputData {
	GPtrArray *output_data;                           /* GPtrArray of arrays of NmcOutputField structs - accumulates data for output */
} NmcOutputData;

/* NmCli - main structure */
typedef struct _NmCli {
	NMClient *client;                                 /* Pointer to NMClient of libnm */

	NMCResultCode return_value;                       /* Return code of nmcli */
	GString *return_text;                             /* Reason text */
	pid_t pager_pid;                                  /* PID of a pager, if one was spawned */

	int timeout;                                      /* Operation timeout */

	NMSecretAgentSimple *secret_agent;                /* Secret agent */
	GHashTable *pwds_hash;                            /* Hash table with passwords in passwd-file */
	struct _NMPolkitListener *pk_listener;            /* polkit agent listener */

	int should_wait;                                  /* Semaphore indicating whether nmcli should not end or not yet */
	gboolean nowait_flag;                             /* '--nowait' option; used for passing to callbacks */
	gboolean mode_specified;                          /* Whether tabular/multiline mode was specified via '--mode' option */
	union {
		const NmcConfig nmc_config;
		NmcConfig nmc_config_mutable;
	};
	char *required_fields;                            /* Required fields in output: '--fields' option */
	gboolean ask;                                     /* Ask for missing parameters: option '--ask' */
	gboolean complete;                                /* Autocomplete the command line */
	gboolean editor_status_line;                      /* Whether to display status line in connection editor */
	gboolean editor_save_confirmation;                /* Whether to ask for confirmation on saving connections with 'autoconnect=yes' */

	char *palette_buffer;                             /* Buffer with sequences for terminal-colors.d(5)-based coloring. */
} NmCli;

#define NMC_RETURN(nmc, rvalue) \
	G_STMT_START { \
		return ((nmc)->return_value = (rvalue)); \
	} G_STMT_END

extern NmCli nm_cli;

/* Error quark for GError domain */
#define NMCLI_ERROR (nmcli_error_quark ())
GQuark nmcli_error_quark (void);

extern GMainLoop *loop;

gboolean nmc_seen_sigint (void);
void     nmc_clear_sigint (void);
void     nmc_set_sigquit_internal (void);
void     nmc_exit (void);

void nm_cli_spawn_pager (NmCli *nmc);

void nmc_empty_output_fields (NmcOutputData *output_data);

#define NMC_OUTPUT_DATA_DEFINE_SCOPED(out) \
	gs_unref_array GArray *out##_indices = NULL; \
	nm_auto (nmc_empty_output_fields) NmcOutputData out = { \
		.output_data = g_ptr_array_new_full (20, g_free), \
	}

#endif /* NMC_NMCLI_H */
