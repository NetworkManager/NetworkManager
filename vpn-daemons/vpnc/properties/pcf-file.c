#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include "pcf-file.h"

static void
pcf_entry_free (PcfEntry *entry)
{
	if (entry) {
		g_free (entry->key);
		g_free (entry->value);
		g_free (entry);
	}
}

/*
  The main reader loop here is based on the simple .ini file
  parser from avahi/avahi-daemon/ini-file-parser.c
*/

GHashTable *
pcf_file_load (const char *fname)
{
	FILE *fo;
	unsigned line;
    GHashTable *pcf;
	GHashTable *group = NULL;
    
    g_return_val_if_fail (fname != NULL, NULL);

    if (!(fo = fopen (fname, "r"))) {
        g_warning ("Failed to open file '%s': %s", fname, strerror (errno));
        return NULL;
    }

	pcf = g_hash_table_new_full (g_str_hash, g_str_equal,
								 g_free,
								 (GDestroyNotify) g_hash_table_destroy);

    line = 0;
    while (!feof (fo)) {
        char ln[256], *s, *e;
        
        if (!(fgets (ln, sizeof (ln), fo)))
            break;

        line++;

        s = ln + strspn (ln, " \t");
        s[strcspn (s, "\r\n")] = 0;

        /* Skip comments and empty lines */
        if (*s == ';' || *s == 0)
            continue;

        if (*s == '[') {
            /* new group */
            
            if (!(e = strchr (s, ']'))) {
                g_warning ("Unclosed group header in %s:%u: <%s>", fname, line, s);
                goto fail;
            }

            *e = 0;

			group = g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
										   (GDestroyNotify) pcf_entry_free);

			g_hash_table_insert (pcf, g_utf8_strdown (s+1, -1), group);
        } else {
			PcfEntry *entry;

            /* Normal assignment */
            if (!(e = strchr (s, '='))) {
                g_warning ("Missing assignment in %s:%u: <%s>", fname, line, s);
                goto fail;
            }
            
            if (!group) {
                g_warning ("Assignment outside group in %s:%u <%s>", fname, line, s);
                goto fail;
            }
            
            /* Split the key and the value */
            *(e++) = 0;

			entry = g_new (PcfEntry, 1);
			entry->value = g_strdup (e);

			if (*s == '!') {
				entry->key = g_utf8_strdown (s+1, -1);
				entry->read_only = TRUE;
			} else {
				entry->key = g_utf8_strdown (s, -1);
				entry->read_only = FALSE;
			}

			g_hash_table_insert (group, entry->key, entry);
        }
    }
    
    fclose (fo);
        
    return pcf;

fail:

    if (fo)
        fclose (fo);

    if (pcf)
        g_hash_table_destroy (pcf);

    return NULL;
}

PcfEntry *
pcf_file_lookup (GHashTable *pcf_file,
				 const char *group,
				 const char *key)
{
	gpointer section;
	PcfEntry *entry = NULL;
	char *group_lower = NULL;
	char *key_lower = NULL;

	g_return_val_if_fail (pcf_file != NULL, NULL);
	g_return_val_if_fail (group != NULL, NULL);
	g_return_val_if_fail (key != NULL, NULL);

	group_lower = g_utf8_strdown (group, -1);
	section = g_hash_table_lookup (pcf_file, group_lower);
	if (section) {
		key_lower = g_utf8_strdown (key, -1);
		entry = (PcfEntry *) g_hash_table_lookup ((GHashTable *) section, key_lower);
	}

	g_free (group_lower);
	g_free (key_lower);

	return entry;
}

const char *
pcf_file_lookup_value (GHashTable *pcf_file,
					   const char *group,
					   const char *key)
{
	PcfEntry *entry;

	entry = pcf_file_lookup (pcf_file, group, key);
	if (entry)
		return entry->value;

	return NULL;
}
