#ifndef NM_HAL_MANAGER_H
#define NM_HAL_MANAGER_H

#include "nm-manager.h"

typedef struct _NMHalManager NMHalManager;

NMHalManager *nm_hal_manager_new (NMManager *nm_manager);
void nm_hal_manager_destroy (NMHalManager *manager);

#endif /* NM_HAL_MANAGER_H */
