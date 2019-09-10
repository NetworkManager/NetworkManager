// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright 2019 Red Hat, Inc.
 */

#ifndef __NM_JSON_AUX_H__
#define __NM_JSON_AUX_H__

/*****************************************************************************/

static inline GString *
nm_json_aux_gstr_append_delimiter (GString *gstr)
{
	g_string_append (gstr, ", ");
	return gstr;
}

void nm_json_aux_gstr_append_string_len (GString *gstr,
                                         const char *str,
                                         gsize n);

void nm_json_aux_gstr_append_string (GString *gstr,
                                     const char *str);

static inline void
nm_json_aux_gstr_append_bool (GString *gstr,
                              gboolean v)
{
	g_string_append (gstr, v ? "true" : "false");
}

static inline void
nm_json_aux_gstr_append_int64 (GString *gstr,
                               gint64 v)
{
	g_string_append_printf (gstr, "%"G_GINT64_FORMAT, v);
}

void nm_json_aux_gstr_append_obj_name (GString *gstr,
                                       const char *key,
                                       char start_container);

/*****************************************************************************/

#ifdef NM_VALUE_TYPE_DEFINE_FUNCTIONS
#include "nm-value-type.h"
static inline void
nm_value_type_to_json (NMValueType value_type,
                       GString *gstr,
                       gconstpointer p_field)
{
	nm_assert (p_field);
	nm_assert (gstr);

	switch (value_type) {
	case NM_VALUE_TYPE_BOOL:   nm_json_aux_gstr_append_bool   (gstr, *((const bool        *) p_field)); return;
	case NM_VALUE_TYPE_INT32:  nm_json_aux_gstr_append_int64  (gstr, *((const gint32      *) p_field)); return;
	case NM_VALUE_TYPE_INT:    nm_json_aux_gstr_append_int64  (gstr, *((const int         *) p_field)); return;
	case NM_VALUE_TYPE_STRING: nm_json_aux_gstr_append_string (gstr, *((const char *const *) p_field)); return;
	case NM_VALUE_TYPE_UNSPEC:
		break;
	}
	nm_assert_not_reached ();
}
#endif

/*****************************************************************************/

#endif  /* __NM_JSON_AUX_H__ */
