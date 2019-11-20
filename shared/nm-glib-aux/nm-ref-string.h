// SPDX-License-Identifier: LGPL-2.1+

#ifndef __NM_REF_STRING_H__
#define __NM_REF_STRING_H__

/*****************************************************************************/

typedef struct _NMRefString {
	const char *const str;
	const gsize len;
} NMRefString;

/*****************************************************************************/

NMRefString *nm_ref_string_new_len (const char *cstr, gsize len);

static inline NMRefString *
nm_ref_string_new (const char *cstr)
{
	return   cstr
	       ? nm_ref_string_new_len (cstr, strlen (cstr))
	       : NULL;
}

NMRefString *nm_ref_string_ref (NMRefString *rstr);
void _nm_ref_string_unref_non_null (NMRefString *rstr);

static inline void
nm_ref_string_unref (NMRefString *rstr)
{
	if (rstr)
		_nm_ref_string_unref_non_null (rstr);
}

NM_AUTO_DEFINE_FCN_VOID0 (NMRefString *, _nm_auto_ref_string, _nm_ref_string_unref_non_null)
#define nm_auto_ref_string nm_auto(_nm_auto_ref_string)

/*****************************************************************************/

static inline const char *
nm_ref_string_get_str (NMRefString *rstr)
{
	return rstr ? rstr->str : NULL;
}

static inline gsize
nm_ref_string_get_len (NMRefString *rstr)
{
	return rstr ? rstr->len : 0u;
}

static inline gboolean
NM_IS_REF_STRING (const NMRefString *rstr)
{
#if NM_MORE_ASSERTS > 10
	if (rstr) {
		nm_auto_ref_string NMRefString *r2 = NULL;

		r2 = nm_ref_string_new_len (rstr->str, rstr->len);
		nm_assert (rstr == r2);
	}
#endif

	/* Technically, %NULL is also a valid NMRefString (according to nm_ref_string_new(),
	 * nm_ref_string_get_str() and nm_ref_string_unref()). However, NM_IS_REF_STRING()
	 * does not think so. If callers want to allow %NULL, they need to check
	 * separately. */
	return !!rstr;
}

#endif /* __NM_REF_STRING_H__ */
