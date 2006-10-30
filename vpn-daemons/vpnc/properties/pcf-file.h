#ifndef PCF_FILE_H
#define PCF_FILE_H

#include <glib.h>

typedef struct PcfEntry PcfEntry;

struct PcfEntry {
	char *key;
	char *value;
	gboolean read_only;
};

GHashTable  *pcf_file_load        (const char *fname);
PcfEntry    *pcf_file_lookup      (GHashTable *pcf_file,
								   const char *group,
								   const char *key);

const char *pcf_file_lookup_value (GHashTable *pcf_file,
								   const char *group,
								   const char *key);

#endif /* PCF_FILE_H */
