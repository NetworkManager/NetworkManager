#ifndef NM_HAL_MANAGER_H
#define NM_HAL_MANAGER_H

#include <glib/gtypes.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define NM_TYPE_HAL_MANAGER            (nm_hal_manager_get_type ())
#define NM_HAL_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_HAL_MANAGER, NMHalManager))
#define NM_HAL_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_HAL_MANAGER, NMHalManagerClass))
#define NM_IS_HAL_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_HAL_MANAGER))
#define NM_IS_HAL_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_HAL_MANAGER))
#define NM_HAL_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_HAL_MANAGER, NMHalManagerClass))

typedef struct {
	GObject parent;
} NMHalManager;

typedef GObject *(*NMDeviceCreatorFn) (NMHalManager *manager,
                                       const char *udi,
                                       gboolean managed);

typedef struct {
	GObjectClass parent;

	/* Virtual functions */
	void (*udi_added) (NMHalManager *manager,
	                   const char *udi,
	                   const char *type_name,
	                   NMDeviceCreatorFn creator_fn);

	void (*udi_removed) (NMHalManager *manager, const char *udi);

	void (*rfkill_changed) (NMHalManager *manager, gboolean hw_enabled);

	void (*hal_reappeared) (NMHalManager *manager);
} NMHalManagerClass;

GType nm_hal_manager_get_type (void);

NMHalManager *nm_hal_manager_new (void);
gboolean nm_hal_manager_get_rfkilled (NMHalManager *manager);
void nm_hal_manager_query_devices (NMHalManager *manager);
gboolean nm_hal_manager_udi_exists (NMHalManager *manager, const char *udi);

#endif /* NM_HAL_MANAGER_H */
