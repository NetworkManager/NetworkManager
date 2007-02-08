#ifndef NM_HAL_MANAGER_H
#define NM_HAL_MANAGER_H

#include "nm-manager.h"
#include "NetworkManagerMain.h"

typedef struct _NMHalManager NMHalManager;

NMHalManager *nm_hal_manager_new (NMManager *nm_manager, NMData *nm_data);
void nm_hal_manager_destroy (NMHalManager *manager);

#endif /* NM_HAL_MANAGER_H */
