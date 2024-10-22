/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NMCS_PROVIDER_OCI_H__
#define __NMCS_PROVIDER_OCI_H__

#include "nmcs-provider.h"

/*****************************************************************************/

typedef struct _NMCSProviderOCI      NMCSProviderOCI;
typedef struct _NMCSProviderOCIClass NMCSProviderOCIClass;

#define NMCS_TYPE_PROVIDER_OCI (nmcs_provider_oci_get_type())
#define NMCS_PROVIDER_OCI(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NMCS_TYPE_PROVIDER_OCI, NMCSProviderOCI))
#define NMCS_PROVIDER_OCI_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMCS_TYPE_PROVIDER_OCI, NMCSProviderOCIClass))
#define NMCS_IS_PROVIDER_OCI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMCS_TYPE_PROVIDER_OCI))
#define NMCS_IS_PROVIDER_OCI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NMCS_TYPE_PROVIDER_OCI))
#define NMCS_PROVIDER_OCI_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMCS_TYPE_PROVIDER_OCI, NMCSProviderOCIClass))

GType nmcs_provider_oci_get_type(void);

/*****************************************************************************/

#endif /* __NMCS_PROVIDER_OCI_H__ */
