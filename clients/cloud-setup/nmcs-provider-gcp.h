// SPDX-License-Identifier: LGPL-2.1+

#ifndef __NMCS_PROVIDER_GCP_H__
#define __NMCS_PROVIDER_GCP_H__

#include "nmcs-provider.h"

/*****************************************************************************/

typedef struct _NMCSProviderGCP      NMCSProviderGCP;
typedef struct _NMCSProviderGCPClass NMCSProviderGCPClass;

#define NMCS_TYPE_PROVIDER_GCP            (nmcs_provider_gcp_get_type ())
#define NMCS_PROVIDER_GCP(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMCS_TYPE_PROVIDER_GCP, NMCSProviderGCP))
#define NMCS_PROVIDER_GCP_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMCS_TYPE_PROVIDER_GCP, NMCSProviderGCPClass))
#define NMCS_IS_PROVIDER_GCP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMCS_TYPE_PROVIDER_GCP))
#define NMCS_IS_PROVIDER_GCP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMCS_TYPE_PROVIDER_GCP))
#define NMCS_PROVIDER_GCP_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMCS_TYPE_PROVIDER_GCP, NMCSProviderGCPClass))

GType nmcs_provider_gcp_get_type (void);

/*****************************************************************************/

#endif /* __NMCS_PROVIDER_GCP_H__ */
