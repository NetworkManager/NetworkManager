#ifndef NMVPNUI_VALIDATE_H
#define NMVPNUI_VALIDATE_H

#define STORAGE_CLASS extern
#ifdef NMVPNUI_VALIDATE_C
#undef STORAGE_CLASS 
#define STORAGE_CLASS 
#endif

STORAGE_CLASS gboolean vld_non_empty (VpnUIConfigOption *value);
STORAGE_CLASS gboolean vld_non_empty_no_ws (VpnUIConfigOption *value);
STORAGE_CLASS gboolean vld_routes_if_sens (VpnUIConfigOption *value);

#undef STORAGE_CLASS
#endif
