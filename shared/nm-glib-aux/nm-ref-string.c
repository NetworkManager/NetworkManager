// SPDX-License-Identifier: LGPL-2.1+

#include "nm-default.h"

#include "nm-ref-string.h"

/*****************************************************************************/

typedef struct {
	NMRefString r;
	volatile int ref_count;
	char str_data[];
} RefString;

G_LOCK_DEFINE_STATIC (gl_lock);
static GHashTable *gl_hash;

/* the first field of NMRefString is a pointer to the NUL terminated string.
 * This also allows to compare strings with nm_pstr_equal(), although, pointer
 * equality might be better. */
G_STATIC_ASSERT (G_STRUCT_OFFSET (NMRefString, str) == 0);
G_STATIC_ASSERT (G_STRUCT_OFFSET (RefString, r) == 0);
G_STATIC_ASSERT (G_STRUCT_OFFSET (RefString, r.str) == 0);

/*****************************************************************************/

static guint
_ref_string_hash (gconstpointer ptr)
{
	const RefString *a = ptr;
	NMHashState h;

	nm_hash_init (&h, 1463435489u);
	nm_hash_update (&h, a->r.str, a->r.len);
	return nm_hash_complete (&h);
}

static gboolean
_ref_string_equal (gconstpointer pa, gconstpointer pb)
{
	const RefString *a = pa;
	const RefString *b = pb;

	return    a->r.len == b->r.len
	       && memcmp (a->r.str, b->r.str, a->r.len) == 0;
}

/*****************************************************************************/

static void
_ASSERT (const RefString *rstr0)
{
	int r;

	nm_assert (rstr0);

	G_LOCK (gl_lock);
	r = g_atomic_int_get (&rstr0->ref_count);

	nm_assert (r > 0);
	nm_assert (r < G_MAXINT);

	nm_assert (rstr0 == g_hash_table_lookup (gl_hash, rstr0));
	G_UNLOCK (gl_lock);
}

/**
 * nm_ref_string_new_len:
 * @cstr: the string to intern. Must contain @len bytes.
 *   If @len is zero, @cstr may be %NULL. Note that it is
 *   accetable that the string contains a NUL character
 *   within the first @len bytes. That is, the string is
 *   not treated as a NUL terminated string, but as binary.
 *   Also, contrary to strncpy(), this will read all the
 *   first @len bytes. It won't stop at the first NUL.
 * @len: the length of the string (usually there is no NUL character
 *   within the first @len bytes, but that would be acceptable as well
 *   to add binary data).
 *
 * Note that the resulting NMRefString instance will always be NUL terminated
 * (at position @len).
 *
 * Note that NMRefString are always interned/deduplicated. If such a string
 * already exists, the existing instance will be refered and returned.
 *
 *
 * Since all NMRefString are shared and interned, you may use
 * pointer equality to compare them. Note that if a NMRefString contains
 * a NUL character (meaning, if
 *
 *    strlen (nm_ref_string_get_str (str)) != nm_ref_string_get_len (str)
 *
 * ), then pointer in-equality does not mean that the NUL terminated strings
 * are also unequal. In other words, for strings that contain NUL characters,
 *
 *    if (str1 != str2)
 *       assert (!nm_streq0 (nm_ref_string_get_str (str1), nm_ref_string_get_str (str2)));
 *
 * might not hold!
 *
 *
 * NMRefString is thread-safe.
 *
 * Returns: (transfer full): the interned string. This is
 *   never %NULL, but note that %NULL is also a valid NMRefString.
 *   The result must be unrefed with nm_ref_string_unref().
 */
NMRefString *
nm_ref_string_new_len (const char *cstr, gsize len)
{
	RefString *rstr0;

	G_LOCK (gl_lock);

	if (G_UNLIKELY (!gl_hash)) {
		gl_hash = g_hash_table_new_full (_ref_string_hash, _ref_string_equal, g_free, NULL);
		rstr0 = NULL;
	} else {
		NMRefString rr_lookup = {
			.len = len,
			.str = cstr,
		};

		rstr0 = g_hash_table_lookup (gl_hash, &rr_lookup);
	}

	if (rstr0) {
		nm_assert (({
		               int r = g_atomic_int_get (&rstr0->ref_count);

		               (r >= 0 && r < G_MAXINT);
		            }));
		g_atomic_int_inc (&rstr0->ref_count);
	} else {
		rstr0 = g_malloc (sizeof (RefString) + 1 + len);
		rstr0->ref_count = 1;
		*((gsize *) rstr0->r.len) = len;
		*((const char **) rstr0->r.str) = rstr0->str_data;
		if (len > 0)
			memcpy (rstr0->str_data, cstr, len);
		rstr0->str_data[len] = '\0';

		if (!g_hash_table_add (gl_hash, rstr0))
			nm_assert_not_reached ();
	}

	G_UNLOCK (gl_lock);

	return &rstr0->r;
}

NMRefString *
nm_ref_string_ref (NMRefString *rstr)
{
	RefString *const rstr0 = (RefString *) rstr;

	if (!rstr)
		return NULL;

	_ASSERT (rstr0);

	g_atomic_int_inc (&rstr0->ref_count);
	return &rstr0->r;
}

void
_nm_ref_string_unref_non_null (NMRefString *rstr)
{
	RefString *const rstr0 = (RefString *) rstr;

	_ASSERT (rstr0);

	if (G_LIKELY (!g_atomic_int_dec_and_test (&rstr0->ref_count)))
		return;

	G_LOCK (gl_lock);

	/* in the fast-path above, we already decremented the ref-count to zero.
	 * We need recheck that the ref-count is still zero. */

	if (g_atomic_int_get (&rstr0->ref_count) == 0)
		g_hash_table_remove (gl_hash, rstr0);

	G_UNLOCK (gl_lock);
}

/*****************************************************************************/
