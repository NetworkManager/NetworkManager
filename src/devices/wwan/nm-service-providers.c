// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2009 Novell, Inc.
 * Author: Tambet Ingo (tambet@gmail.com).
 * Copyright (C) 2009 - 2019 Red Hat, Inc.
 * Copyright (C) 2012 Lanedo GmbH
 */

#include "nm-default.h"

#include "nm-service-providers.h"

typedef enum {
	PARSER_TOPLEVEL = 0,
	PARSER_COUNTRY,
	PARSER_PROVIDER,
	PARSER_METHOD_GSM,
	PARSER_METHOD_GSM_APN,
	PARSER_METHOD_CDMA,
	PARSER_DONE,
	PARSER_ERROR
} ParseContextState;

typedef struct {
	char *mccmnc;
	NMServiceProvidersGsmApnCallback callback;
	gpointer user_data;
	GCancellable *cancellable;
	GMarkupParseContext *ctx;
	char buffer[4096];

	char *text_buffer;
	ParseContextState state;

	gboolean mccmnc_matched;
	gboolean found_internet_apn;
	char *apn;
	char *username;
	char *password;
	char *gateway;
	char *auth_method;
	GSList *dns;
} ParseContext;

/*****************************************************************************/

static void
parser_toplevel_start (ParseContext *parse_context,
                       const char *name,
                       const char **attribute_names,
                       const char **attribute_values)
{
	int i;

	if (strcmp (name, "serviceproviders") == 0) {
		for (i = 0; attribute_names && attribute_names[i]; i++) {
			if (strcmp (attribute_names[i], "format") == 0) {
				if (strcmp (attribute_values[i], "2.0")) {
					g_warning ("%s: mobile broadband provider database format '%s'"
					           " not supported.", __func__, attribute_values[i]);
					parse_context->state = PARSER_ERROR;
					break;
				}
			}
		}
	} else if (strcmp (name, "country") == 0) {
		parse_context->state = PARSER_COUNTRY;
	}
}

static void
parser_country_start (ParseContext *parse_context,
                      const char *name,
                      const char **attribute_names,
                      const char **attribute_values)
{
	if (strcmp (name, "provider") == 0)
		parse_context->state = PARSER_PROVIDER;
}

static void
parser_provider_start (ParseContext *parse_context,
                       const char *name,
                       const char **attribute_names,
                       const char **attribute_values)
{
	parse_context->mccmnc_matched = FALSE;
	if (strcmp (name, "gsm") == 0)
		parse_context->state = PARSER_METHOD_GSM;
	else if (strcmp (name, "cdma") == 0)
		parse_context->state = PARSER_METHOD_CDMA;
}

static void
parser_gsm_start (ParseContext *parse_context,
                  const char *name,
                  const char **attribute_names,
                  const char **attribute_values)
{
	int i;

	if (strcmp (name, "network-id") == 0) {
		const char *mcc = NULL, *mnc = NULL;

		for (i = 0; attribute_names && attribute_names[i]; i++) {
			if (strcmp (attribute_names[i], "mcc") == 0)
				mcc = attribute_values[i];
			else if (strcmp (attribute_names[i], "mnc") == 0)
				mnc = attribute_values[i];
			if (mcc && strlen (mcc) && mnc && strlen (mnc)) {
				char *mccmnc = g_strdup_printf ("%s%s", mcc, mnc);

				if (strcmp (mccmnc, parse_context->mccmnc) == 0)
					parse_context->mccmnc_matched = TRUE;
				g_free (mccmnc);
				break;
			}
		}
	} else if (strcmp (name, "apn") == 0) {
		parse_context->found_internet_apn = FALSE;
		nm_clear_g_free (&parse_context->apn);
		nm_clear_g_free (&parse_context->username);
		nm_clear_g_free (&parse_context->password);
		nm_clear_g_free (&parse_context->gateway);
		nm_clear_g_free (&parse_context->auth_method);
		g_slist_free_full (parse_context->dns, g_free);
		parse_context->dns = NULL;

		for (i = 0; attribute_names && attribute_names[i]; i++) {
			if (strcmp (attribute_names[i], "value") == 0) {
				parse_context->state = PARSER_METHOD_GSM_APN;
				parse_context->apn = g_strstrip (g_strdup (attribute_values[i]));
				break;
			}
		}
	}
}

static void
parser_gsm_apn_start (ParseContext *parse_context,
                  const char *name,
                  const char **attribute_names,
                  const char **attribute_values)
{
	int i;

	if (strcmp (name, "usage") == 0) {
		for (i = 0; attribute_names && attribute_names[i]; i++) {
			if (   (strcmp (attribute_names[i], "type") == 0)
			    && (strcmp (attribute_values[i], "internet") == 0)) {
				parse_context->found_internet_apn = TRUE;
				break;
			}
		}
	} else if (strcmp (name, "authentication") == 0) {
		for (i = 0; attribute_names && attribute_names[i]; i++) {
			if (strcmp (attribute_names[i], "method") == 0) {
				nm_clear_g_free (&parse_context->auth_method);
				parse_context->auth_method = g_strstrip (g_strdup (attribute_values[i]));
				break;
			}
		}
	}
}

static void
parser_start_element (GMarkupParseContext *context,
                             const char *element_name,
                             const char **attribute_names,
                             const char **attribute_values,
                             gpointer user_data,
                             GError **error)
{
	ParseContext *parse_context = user_data;

	nm_clear_g_free (&parse_context->text_buffer);

	switch (parse_context->state) {
	case PARSER_TOPLEVEL:
		parser_toplevel_start (parse_context, element_name, attribute_names, attribute_values);
		break;
	case PARSER_COUNTRY:
		parser_country_start (parse_context, element_name, attribute_names, attribute_values);
		break;
	case PARSER_PROVIDER:
		parser_provider_start (parse_context, element_name, attribute_names, attribute_values);
		break;
	case PARSER_METHOD_GSM:
		parser_gsm_start (parse_context, element_name, attribute_names, attribute_values);
		break;
	case PARSER_METHOD_GSM_APN:
		parser_gsm_apn_start (parse_context, element_name, attribute_names, attribute_values);
		break;
	case PARSER_METHOD_CDMA:
		break;
	case PARSER_ERROR:
		break;
	case PARSER_DONE:
		break;
	}
}

static void
parser_country_end (ParseContext *parse_context,
                    const char *name)
{
	if (strcmp (name, "country") == 0) {
		nm_clear_g_free (&parse_context->text_buffer);
		parse_context->state = PARSER_TOPLEVEL;
	}
}

static void
parser_provider_end (ParseContext *parse_context,
                     const char *name)
{
	if (strcmp (name, "provider") == 0) {
		nm_clear_g_free (&parse_context->text_buffer);
		parse_context->state = PARSER_COUNTRY;
	}
}

static void
parser_gsm_end (ParseContext *parse_context,
                const char *name)
{
	if (strcmp (name, "gsm") == 0) {
		nm_clear_g_free (&parse_context->text_buffer);
		parse_context->state = PARSER_PROVIDER;
	}
}

static void
parser_gsm_apn_end (ParseContext *parse_context,
                    const char *name)
{
	if (strcmp (name, "username") == 0) {
		nm_clear_g_free (&parse_context->username);
		parse_context->username = g_steal_pointer (&parse_context->text_buffer);
	} else if (strcmp (name, "password") == 0) {
		nm_clear_g_free (&parse_context->password);
		parse_context->password = g_steal_pointer (&parse_context->text_buffer);
	} else if (strcmp (name, "dns") == 0) {
		parse_context->dns = g_slist_prepend (parse_context->dns,
		                                   g_steal_pointer (&parse_context->text_buffer));
	} else if (strcmp (name, "gateway") == 0) {
		nm_clear_g_free (&parse_context->gateway);
		parse_context->gateway = g_steal_pointer (&parse_context->text_buffer);
	} else if (strcmp (name, "apn") == 0) {
		nm_clear_g_free (&parse_context->text_buffer);

		if (parse_context->mccmnc_matched && parse_context->found_internet_apn)
			parse_context->state = PARSER_DONE;
		else
			parse_context->state = PARSER_METHOD_GSM;

	}
}

static void
parser_cdma_end (ParseContext *parse_context,
                 const char *name)
{
	if (strcmp (name, "cdma") == 0) {
		nm_clear_g_free (&parse_context->text_buffer);
		parse_context->state = PARSER_PROVIDER;
	}
}

static void
parser_end_element (GMarkupParseContext *context,
                           const char *element_name,
                           gpointer user_data,
                           GError **error)
{
	ParseContext *parse_context = user_data;

	switch (parse_context->state) {
	case PARSER_TOPLEVEL:
		break;
	case PARSER_COUNTRY:
		parser_country_end (parse_context, element_name);
		break;
	case PARSER_PROVIDER:
		parser_provider_end (parse_context, element_name);
		break;
	case PARSER_METHOD_GSM:
		parser_gsm_end (parse_context, element_name);
		break;
	case PARSER_METHOD_GSM_APN:
		parser_gsm_apn_end (parse_context, element_name);
		break;
	case PARSER_METHOD_CDMA:
		parser_cdma_end (parse_context, element_name);
		break;
	case PARSER_ERROR:
		break;
	case PARSER_DONE:
		break;
	}
}

static void
parser_text (GMarkupParseContext *context,
             const char *text,
             gsize text_len,
             gpointer user_data,
             GError **error)
{
	ParseContext *parse_context = user_data;

	g_free (parse_context->text_buffer);
	parse_context->text_buffer = g_strdup (text);
}

static const GMarkupParser parser = {
	.start_element  = parser_start_element,
	.end_element    = parser_end_element,
	.text           = parser_text,
	.passthrough    = NULL,
	.error          = NULL,
};

/*****************************************************************************/

static void
finish_parse_context (ParseContext *parse_context, GError *error)
{
	if (parse_context->callback) {
		if (error) {
			parse_context->callback (NULL, NULL, NULL, NULL, NULL,
			                         NULL, error,
			                         parse_context->user_data);
		} else {
			parse_context->callback (parse_context->apn,
			                         parse_context->username,
			                         parse_context->password,
			                         parse_context->gateway,
			                         parse_context->auth_method,
			                         parse_context->dns,
			                         error,
			                         parse_context->user_data);
		}
	}

	g_free (parse_context->mccmnc);
	g_markup_parse_context_free (parse_context->ctx);

	g_free (parse_context->text_buffer);
	g_free (parse_context->apn);
	g_free (parse_context->username);
	g_free (parse_context->password);
	g_free (parse_context->gateway);
	g_free (parse_context->auth_method);
	g_slist_free_full (parse_context->dns, g_free);

	g_slice_free (ParseContext, parse_context);
}

static void
read_next_chunk (GInputStream *stream, ParseContext *parse_context);

static void
stream_read_cb (GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	GInputStream *stream = G_INPUT_STREAM (source_object);
	ParseContext *parse_context = user_data;
	gssize len;
	GError *error = NULL;

	len = g_input_stream_read_finish (stream, res, &error);
	if (len == -1) {
		g_prefix_error (&error, "Error reading service provider database: ");
		finish_parse_context (parse_context, error);
		g_clear_error (&error);
		return;
	}

	if (len == 0) {
		g_set_error (&error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "Operator ID '%s' not found in service provider database",
		             parse_context->mccmnc);
		finish_parse_context (parse_context, error);
		g_clear_error (&error);
		return;
	}

	if (!g_markup_parse_context_parse (parse_context->ctx, parse_context->buffer, len, &error)) {
		g_prefix_error (&error, "Error parsing service provider database: ");
		finish_parse_context (parse_context, error);
		g_clear_error (&error);
		return;
	}

	if (parse_context->state == PARSER_DONE) {
		finish_parse_context (parse_context, NULL);
		return;
	}

	read_next_chunk (stream, parse_context);
}

static void
read_next_chunk (GInputStream *stream, ParseContext *parse_context)
{
	g_input_stream_read_async (stream,
	                           parse_context->buffer,
	                           sizeof (parse_context->buffer),
	                           G_PRIORITY_DEFAULT,
	                           parse_context->cancellable,
	                           stream_read_cb,
	                           parse_context);
}

static void
file_read_cb (GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	GFile *file = G_FILE (source_object);
	ParseContext *parse_context = user_data;
	GFileInputStream *stream;
	gs_free_error GError *error = NULL;

	stream = g_file_read_finish (file, res, &error);
	if (!stream) {
		g_prefix_error (&error, "Error opening service provider database: ");
		finish_parse_context (parse_context, error);
		return;
	}

	read_next_chunk (G_INPUT_STREAM (stream), parse_context);

	g_object_unref (stream);
}

/*****************************************************************************/

void
nm_service_providers_find_gsm_apn (const char *service_providers,
                                   const char *mccmnc,
                                   GCancellable *cancellable,
                                   NMServiceProvidersGsmApnCallback callback,
                                   gpointer user_data)
{
	GFile *file;
	ParseContext *parse_context;

	parse_context = g_slice_new0 (ParseContext);
	parse_context->mccmnc = g_strdup (mccmnc);
	parse_context->cancellable = cancellable;
	parse_context->callback = callback;
	parse_context->user_data = user_data;
	parse_context->ctx = g_markup_parse_context_new (&parser, 0, parse_context, NULL);

	file = g_file_new_for_path (service_providers);

	g_file_read_async (file, G_PRIORITY_DEFAULT, cancellable, file_read_cb, parse_context);

	g_object_unref (file);
}
