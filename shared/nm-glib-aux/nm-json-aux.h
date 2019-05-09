/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
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

#endif  /* __NM_JSON_AUX_H__ */
