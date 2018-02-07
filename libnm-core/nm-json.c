/*
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
 * Copyright 2017, 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#define NM_JANSSON_C
#include "nm-json.h"

#include <dlfcn.h>

void *_nm_jansson_json_object_iter_value;
void *_nm_jansson_json_object_key_to_iter;
void *_nm_jansson_json_integer;
void *_nm_jansson_json_object_del;
void *_nm_jansson_json_array_get;
void *_nm_jansson_json_array_size;
void *_nm_jansson_json_array_append_new;
void *_nm_jansson_json_string;
void *_nm_jansson_json_object_iter_next;
void *_nm_jansson_json_loads;
void *_nm_jansson_json_dumps;
void *_nm_jansson_json_object_iter_key;
void *_nm_jansson_json_object;
void *_nm_jansson_json_object_get;
void *_nm_jansson_json_array;
void *_nm_jansson_json_false;
void *_nm_jansson_json_delete;
void *_nm_jansson_json_true;
void *_nm_jansson_json_object_size;
void *_nm_jansson_json_object_set_new;
void *_nm_jansson_json_object_iter;
void *_nm_jansson_json_integer_value;
void *_nm_jansson_json_string_value;

#define TRY_BIND_SYMBOL(symbol) \
	G_STMT_START { \
		void *sym = dlsym (handle, #symbol); \
		if (_nm_jansson_ ## symbol && sym != _nm_jansson_ ## symbol) \
			return FALSE; \
		_nm_jansson_ ## symbol = sym; \
	} G_STMT_END

static gboolean
bind_symbols (void *handle)
{
	TRY_BIND_SYMBOL (json_object_iter_value);
	TRY_BIND_SYMBOL (json_object_key_to_iter);
	TRY_BIND_SYMBOL (json_integer);
	TRY_BIND_SYMBOL (json_object_del);
	TRY_BIND_SYMBOL (json_array_get);
	TRY_BIND_SYMBOL (json_array_size);
	TRY_BIND_SYMBOL (json_array_append_new);
	TRY_BIND_SYMBOL (json_string);
	TRY_BIND_SYMBOL (json_object_iter_next);
	TRY_BIND_SYMBOL (json_loads);
	TRY_BIND_SYMBOL (json_dumps);
	TRY_BIND_SYMBOL (json_object_iter_key);
	TRY_BIND_SYMBOL (json_object);
	TRY_BIND_SYMBOL (json_object_get);
	TRY_BIND_SYMBOL (json_array);
	TRY_BIND_SYMBOL (json_false);
	TRY_BIND_SYMBOL (json_delete);
	TRY_BIND_SYMBOL (json_true);
	TRY_BIND_SYMBOL (json_object_size);
	TRY_BIND_SYMBOL (json_object_set_new);
	TRY_BIND_SYMBOL (json_object_iter);
	TRY_BIND_SYMBOL (json_integer_value);
	TRY_BIND_SYMBOL (json_string_value);

	return TRUE;
}

gboolean
nm_jansson_load (void)
{
	static enum {
		UNKNOWN,
		AVAILABLE,
		MISSING,
	} state = UNKNOWN;
	void *handle;
	int mode;

	if (G_LIKELY (state != UNKNOWN))
		goto out;

	/* First just resolve the symbols to see if there's a conflict already. */
	if (!bind_symbols (RTLD_DEFAULT))
		goto out;

	mode = RTLD_LAZY | RTLD_LOCAL | RTLD_NODELETE | RTLD_DEEPBIND;
#if defined (ASAN_BUILD)
	/* Address sanitizer is incompatible with RTLD_DEEPBIND. */
	mode &= ~RTLD_DEEPBIND;
#endif
	handle = dlopen (JANSSON_SONAME, mode);

	if (!handle)
		goto out;

	/* Now do the actual binding. */
	if (!bind_symbols (handle))
		goto out;

	state = AVAILABLE;
out:
	return state == AVAILABLE;
}
