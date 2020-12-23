/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NMCS_PROVIDER_AZURE_H__
#define __NMCS_PROVIDER_AZURE_H__

#include "nmcs-provider.h"

/*****************************************************************************/

typedef struct _NMCSProviderAzure      NMCSProviderAzure;
typedef struct _NMCSProviderAzureClass NMCSProviderAzureClass;

#define NMCS_TYPE_PROVIDER_AZURE (nmcs_provider_azure_get_type())
#define NMCS_PROVIDER_AZURE(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NMCS_TYPE_PROVIDER_AZURE, NMCSProviderAzure))
#define NMCS_PROVIDER_AZURE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMCS_TYPE_PROVIDER_AZURE, NMCSProviderAzureClass))
#define NMCS_IS_PROVIDER_AZURE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMCS_TYPE_PROVIDER_AZURE))
#define NMCS_IS_PROVIDER_AZURE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NMCS_TYPE_PROVIDER_AZURE))
#define NMCS_PROVIDER_AZURE_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMCS_TYPE_PROVIDER_AZURE, NMCSProviderAzureClass))

GType nmcs_provider_azure_get_type(void);

/*****************************************************************************/

#endif /* __NMCS_PROVIDER_AZURE_H__ */
