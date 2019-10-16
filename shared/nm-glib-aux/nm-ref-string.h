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

#endif /* __NM_REF_STRING_H__ */
