/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright 2008 - 2011 Red Hat, Inc.
 */

#ifndef __NM_GLIB_H__
#define __NM_GLIB_H__


#include <gio/gio.h>
#include <string.h>

#ifdef __clang__

#undef G_GNUC_BEGIN_IGNORE_DEPRECATIONS
#undef G_GNUC_END_IGNORE_DEPRECATIONS

#define G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")

#define G_GNUC_END_IGNORE_DEPRECATIONS \
    _Pragma("clang diagnostic pop")

#endif

static inline void
__g_type_ensure (GType type)
{
#if !GLIB_CHECK_VERSION(2,34,0)
	if (G_UNLIKELY (type == (GType)-1))
		g_error ("can't happen");
#else
	G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
	g_type_ensure (type);
	G_GNUC_END_IGNORE_DEPRECATIONS;
#endif
}
#define g_type_ensure __g_type_ensure

#if !GLIB_CHECK_VERSION(2,34,0)

#define g_clear_pointer(pp, destroy) \
    G_STMT_START {                                                                 \
        G_STATIC_ASSERT (sizeof *(pp) == sizeof (gpointer));                       \
        /* Only one access, please */                                              \
        gpointer *_pp = (gpointer *) (pp);                                         \
        gpointer _p;                                                               \
        /* This assignment is needed to avoid a gcc warning */                     \
        GDestroyNotify _destroy = (GDestroyNotify) (destroy);                      \
                                                                                   \
        _p = *_pp;                                                                 \
        if (_p)                                                                    \
        {                                                                          \
            *_pp = NULL;                                                           \
            _destroy (_p);                                                         \
        }                                                                          \
    } G_STMT_END

/* These are used to clean up the output of test programs; we can just let
 * them no-op in older glib.
 */
#define g_test_expect_message(log_domain, log_level, pattern)
#define g_test_assert_expected_messages()

#else

/* We build with -DGLIB_MAX_ALLOWED_VERSION set to 2.32 to make sure we don't
 * accidentally use new API that we shouldn't. But we don't want warnings for
 * the APIs that we emulate above.
 */

#define g_test_expect_message(domain, level, format...) \
	G_STMT_START { \
		G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
		g_test_expect_message (domain, level, format); \
		G_GNUC_END_IGNORE_DEPRECATIONS \
	} G_STMT_END

#define g_test_assert_expected_messages_internal(domain, file, line, func) \
	G_STMT_START { \
		G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
		g_test_assert_expected_messages_internal (domain, file, line, func); \
		G_GNUC_END_IGNORE_DEPRECATIONS \
	} G_STMT_END

#endif


#if GLIB_CHECK_VERSION (2, 35, 0)
/* For glib >= 2.36, g_type_init() is deprecated.
 * But since 2.35.1 (7c42ab23b55c43ab96d0ac2124b550bf1f49c1ec) this function
 * does nothing. Replace the call with empty statement. */
#define nm_g_type_init()     G_STMT_START { (void) 0; } G_STMT_END
#else
#define nm_g_type_init()     G_STMT_START { g_type_init (); } G_STMT_END
#endif


/* g_test_initialized() is only available since glib 2.36. */
#if !GLIB_CHECK_VERSION (2, 36, 0)
#define g_test_initialized() (g_test_config_vars->test_initialized)
#endif

/* g_test_skip() is only available since glib 2.38. Add a compatibility wrapper. */
inline static void
__nmtst_g_test_skip (const gchar *msg)
{
#if GLIB_CHECK_VERSION (2, 38, 0)
	G_GNUC_BEGIN_IGNORE_DEPRECATIONS
	g_test_skip (msg);
	G_GNUC_END_IGNORE_DEPRECATIONS
#else
	g_debug ("%s", msg);
#endif
}
#define g_test_skip __nmtst_g_test_skip


/* g_test_add_data_func_full() is only available since glib 2.34. Add a compatibility wrapper. */
inline static void
__g_test_add_data_func_full (const char     *testpath,
                             gpointer        test_data,
                             GTestDataFunc   test_func,
                             GDestroyNotify  data_free_func)
{
#if GLIB_CHECK_VERSION (2, 34, 0)
	G_GNUC_BEGIN_IGNORE_DEPRECATIONS
	g_test_add_data_func_full (testpath, test_data, test_func, data_free_func);
	G_GNUC_END_IGNORE_DEPRECATIONS
#else
	g_return_if_fail (testpath != NULL);
	g_return_if_fail (testpath[0] == '/');
	g_return_if_fail (test_func != NULL);

	g_test_add_vtable (testpath, 0, test_data, NULL,
	                   (GTestFixtureFunc) test_func,
	                   (GTestFixtureFunc) data_free_func);
#endif
}
#define g_test_add_data_func_full __g_test_add_data_func_full


#if !GLIB_CHECK_VERSION (2, 34, 0)
#define G_DEFINE_QUARK(QN, q_n)               \
GQuark                                        \
q_n##_quark (void)                            \
{                                             \
	static GQuark q;                          \
                                              \
	if G_UNLIKELY (q == 0)                    \
		q = g_quark_from_static_string (#QN); \
                                              \
	return q;                                 \
}
#endif


static inline gboolean
nm_g_hash_table_replace (GHashTable *hash, gpointer key, gpointer value)
{
	/* glib 2.40 added a return value indicating whether the key already existed
	 * (910191597a6c2e5d5d460e9ce9efb4f47d9cc63c). */
#if GLIB_CHECK_VERSION(2, 40, 0)
	return g_hash_table_replace (hash, key, value);
#else
	gboolean contained = g_hash_table_contains (hash, key);

	g_hash_table_replace (hash, key, value);
	return !contained;
#endif
}

static inline gboolean
nm_g_hash_table_insert (GHashTable *hash, gpointer key, gpointer value)
{
	/* glib 2.40 added a return value indicating whether the key already existed
	 * (910191597a6c2e5d5d460e9ce9efb4f47d9cc63c). */
#if GLIB_CHECK_VERSION(2, 40, 0)
	return g_hash_table_insert (hash, key, value);
#else
	gboolean contained = g_hash_table_contains (hash, key);

	g_hash_table_insert (hash, key, value);
	return !contained;
#endif
}

static inline gboolean
nm_g_hash_table_add (GHashTable *hash, gpointer key)
{
	/* glib 2.40 added a return value indicating whether the key already existed
	 * (910191597a6c2e5d5d460e9ce9efb4f47d9cc63c). */
#if GLIB_CHECK_VERSION(2, 40, 0)
	return g_hash_table_add (hash, key);
#else
	gboolean contained = g_hash_table_contains (hash, key);

	g_hash_table_add (hash, key);
	return !contained;
#endif
}

#if !GLIB_CHECK_VERSION(2, 40, 0) || defined (NM_GLIB_COMPAT_H_TEST)
static inline void
_nm_g_ptr_array_insert (GPtrArray *array,
                        gint       index_,
                        gpointer   data)
{
	g_return_if_fail (array);
	g_return_if_fail (index_ >= -1);
	g_return_if_fail (index_ <= (gint) array->len);

	g_ptr_array_add (array, data);

	if (index_ != -1 && index_ != (gint) (array->len - 1)) {
		memmove (&(array->pdata[index_ + 1]),
		         &(array->pdata[index_]),
		         (array->len - index_ - 1) * sizeof (gpointer));
		array->pdata[index_] = data;
	}
}
#endif
#if !GLIB_CHECK_VERSION(2, 40, 0)
#define g_ptr_array_insert(array, index, data) G_STMT_START { _nm_g_ptr_array_insert (array, index, data); } G_STMT_END
#else
#define g_ptr_array_insert(array, index, data) \
	G_STMT_START { \
		G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
		g_ptr_array_insert (array, index, data); \
		G_GNUC_END_IGNORE_DEPRECATIONS \
	} G_STMT_END
#endif


#if !GLIB_CHECK_VERSION (2, 40, 0)
inline static gboolean
_g_key_file_save_to_file (GKeyFile     *key_file,
                          const gchar  *filename,
                          GError      **error)
{
	gchar *contents;
	gboolean success;
	gsize length;

	g_return_val_if_fail (key_file != NULL, FALSE);
	g_return_val_if_fail (filename != NULL, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	contents = g_key_file_to_data (key_file, &length, NULL);
	g_assert (contents != NULL);

	success = g_file_set_contents (filename, contents, length, error);
	g_free (contents);

	return success;
}
#define g_key_file_save_to_file(key_file, filename, error) \
	_g_key_file_save_to_file (key_file, filename, error)
#else
#define g_key_file_save_to_file(key_file, filename, error) \
	({ \
		gboolean _success; \
		\
		G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
		_success = g_key_file_save_to_file (key_file, filename, error); \
		G_GNUC_END_IGNORE_DEPRECATIONS \
		_success; \
	})
#endif


#if GLIB_CHECK_VERSION (2, 36, 0)
#define g_credentials_get_unix_pid(creds, error) \
	G_GNUC_EXTENSION ({ \
		G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
			(g_credentials_get_unix_pid) ((creds), (error)); \
		G_GNUC_END_IGNORE_DEPRECATIONS \
	})
#else
#define g_credentials_get_unix_pid(creds, error) \
	G_GNUC_EXTENSION ({ \
		struct ucred *native_creds; \
		 \
		native_creds = g_credentials_get_native ((creds), G_CREDENTIALS_TYPE_LINUX_UCRED); \
		g_assert (native_creds); \
		native_creds->pid; \
	})
#endif


#if !GLIB_CHECK_VERSION(2, 40, 0) || defined (NM_GLIB_COMPAT_H_TEST)
static inline gpointer *
_nm_g_hash_table_get_keys_as_array (GHashTable *hash_table,
                                    guint      *length)
{
	GHashTableIter iter;
	gpointer key, *ret;
	guint i = 0;

	g_return_val_if_fail (hash_table, NULL);

	ret = g_new0 (gpointer, g_hash_table_size (hash_table) + 1);
	g_hash_table_iter_init (&iter, hash_table);

	while (g_hash_table_iter_next (&iter, &key, NULL))
		ret[i++] = key;

	ret[i] = NULL;

	if (length)
		*length = i;

	return ret;
}
#endif
#if !GLIB_CHECK_VERSION(2, 40, 0)
#define g_hash_table_get_keys_as_array(hash_table, length) \
	G_GNUC_EXTENSION ({ \
		_nm_g_hash_table_get_keys_as_array (hash_table, length); \
	})
#else
#define g_hash_table_get_keys_as_array(hash_table, length) \
	G_GNUC_EXTENSION ({ \
		G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
			(g_hash_table_get_keys_as_array) ((hash_table), (length)); \
		G_GNUC_END_IGNORE_DEPRECATIONS \
	})
#endif

#endif  /* __NM_GLIB_H__ */
