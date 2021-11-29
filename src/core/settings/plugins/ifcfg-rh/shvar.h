/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 1999 Red Hat, Inc.
 */

#ifndef _SHVAR_H
#define _SHVAR_H

typedef struct _shvarFile shvarFile;

typedef enum {
    SV_KEY_TYPE_ANY            = (1LL << 0),
    SV_KEY_TYPE_ROUTE_SVFORMAT = (1LL << 1),
    SV_KEY_TYPE_IP4_ADDRESS    = (1LL << 2),
    SV_KEY_TYPE_TC             = (1LL << 3),
    SV_KEY_TYPE_USER           = (1LL << 4),
    SV_KEY_TYPE_SRIOV_VF       = (1LL << 5),
    SV_KEY_TYPE_ROUTING_RULE4  = (1LL << 6),
    SV_KEY_TYPE_ROUTING_RULE6  = (1LL << 7),
} SvKeyType;

const char *svFileGetName(const shvarFile *s);

void _nmtst_svFileSetName(shvarFile *s, const char *fileName);
void _nmtst_svFileSetModified(shvarFile *s);

/*****************************************************************************/

shvarFile *svFile_new(const char *name, int fd, const char *content);

/* Create the file <name>, return a shvarFile (never fails) */
shvarFile *svCreateFile(const char *name);

/* Open the file <name>, return shvarFile on success, NULL on failure */
shvarFile *svOpenFile(const char *name, GError **error);

/*****************************************************************************/

const char *svFindFirstNumberedKey(shvarFile *s, const char *key_prefix);

/* Get the value associated with the key, and leave the current pointer
 * pointing at the line containing the value.  The char* returned MUST
 * be freed by the caller.
 */
const char *svGetValue(shvarFile *s, const char *key, char **to_free);
char       *svGetValue_cp(shvarFile *s, const char *key);

const char *svGetValueStr(shvarFile *s, const char *key, char **to_free);
char       *svGetValueStr_cp(shvarFile *s, const char *key);

int svParseBoolean(const char *value, int def);

gint64 svNumberedParseKey(const char *key);

GHashTable *svGetKeys(shvarFile *s, SvKeyType match_key_type);

const char **svGetKeysSorted(shvarFile *s, SvKeyType match_key_type, guint *out_len);

/* return TRUE if <key> resolves to any truth value (e.g. "yes", "y", "true")
 * return FALSE if <key> resolves to any non-truth value (e.g. "no", "n", "false")
 * return <def> otherwise
 */
int svGetValueBoolean(shvarFile *s, const char *key, int def);

NMTernary svGetValueTernary(shvarFile *s, const char *key);

gint64
svGetValueInt64(shvarFile *s, const char *key, guint base, gint64 min, gint64 max, gint64 fallback);

gboolean svGetValueEnum(shvarFile *s, const char *key, GType gtype, int *out_value, GError **error);

/* Set the variable <key> equal to the value <value>.
 * If <key> does not exist, and the <current> pointer is set, append
 * the key=value pair after that line.  Otherwise, prepend the pair
 * to the top of the file.
 */
gboolean svSetValue(shvarFile *s, const char *key, const char *value);
gboolean svSetValueStr(shvarFile *s, const char *key, const char *value);
gboolean svSetValueBoolean(shvarFile *s, const char *key, gboolean value);
gboolean svSetValueBoolean_cond_true(shvarFile *s, const char *key, gboolean value);
gboolean svSetValueInt64(shvarFile *s, const char *key, gint64 value);
gboolean svSetValueInt64_cond(shvarFile *s, const char *key, gboolean do_set, gint64 value);
gboolean svSetValueEnum(shvarFile *s, const char *key, GType gtype, int value);
gboolean svSetValueTernary(shvarFile *s, const char *key, NMTernary value);

gboolean svUnsetValue(shvarFile *s, const char *key);
gboolean svUnsetAll(shvarFile *s, SvKeyType match_key_type);
gboolean svUnsetDirtyWellknown(shvarFile *s, NMTernary new_dirty_value);

/* Write the current contents iff modified.  Returns FALSE on error
 * and TRUE on success.  Do not write if no values have been modified.
 * The mode argument is only used if creating the file, not if
 * re-writing an existing file, and is passed unchanged to the
 * open() syscall.
 */
gboolean svWriteFile(shvarFile *s, int mode, GError **error);

static inline gboolean
svWriteFileWithoutDirtyWellknown(shvarFile *s, int mode, GError **error)
{
    svUnsetDirtyWellknown(s, NM_TERNARY_FALSE);
    return svWriteFile(s, mode, error);
}

/* Close the file descriptor (if open) and free the shvarFile. */
void svCloseFile(shvarFile *s);

const char *svEscape(const char *s, char **to_free);
const char *svUnescape(const char *s, char **to_free);
const char *svUnescape_full(const char *value, char **to_free, gboolean check_utf8);

static inline void
_nm_auto_shvar_file_close(shvarFile **p_s)
{
    if (*p_s) {
        int errsv = errno;

        svCloseFile(*p_s);
        errno = errsv;
    }
}
#define nm_auto_shvar_file_close nm_auto(_nm_auto_shvar_file_close)

void svWarnInvalid(shvarFile *s, const char *file_type, NMLogDomain log_domain);

#endif /* _SHVAR_H */
