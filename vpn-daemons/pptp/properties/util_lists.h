#ifndef NMVPNUI_UTIL_LISTS_H
#define NMVPNUI_UTIL_LISTS_H

#define STORAGE_CLASS extern
#ifdef NMVPNUI_UTIL_LISTS_C
#undef STORAGE_CLASS 
#define STORAGE_CLASS 
#endif

STORAGE_CLASS GSList *list_from_string (const char *string);

#undef STORAGE_CLASS
#endif
