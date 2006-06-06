#include <glib.h>
#include <string.h>

#define NMVPNUI_UTIL_LISTS_C
#include "util_lists.h" 

GSList *
list_from_string (const char *string)
{
  char **entries;
  char **parts;
  char **entry;
  char **part;
  int  i;
  GSList *list=NULL; 

  if (string==NULL) return list;
  entries = g_strsplit(string,";",0);
  
  for (entry=entries; *entry; entry++)
  {
    parts = g_strsplit(*entry,"=",2);
    part=parts;
    if ((!(*part)) || (strlen(*part)==0)) {
      g_strfreev(parts);
      continue;
    }

    list = g_slist_append (list,g_strdup(*part));
    *part++;
   
    if ((!(*part)) || (strlen(*part)==0) || (strcmp("''",*part)==0)) {
      list = g_slist_append (list,g_strdup(""));
    } else {
      list = g_slist_append (list,g_strdup(*part));
    }
    g_strfreev(parts);
  }
  g_strfreev(entries);

  return list;
}
