// SPDX-License-Identifier: LGPL-2.1+

#ifndef __NMCS_PROVIDER_EC2_H__
#define __NMCS_PROVIDER_EC2_H__

#include "nmcs-provider.h"

/*****************************************************************************/

typedef struct _NMCSProviderEC2      NMCSProviderEC2;
typedef struct _NMCSProviderEC2Class NMCSProviderEC2Class;

#define NMCS_TYPE_PROVIDER_EC2            (nmcs_provider_ec2_get_type ())
#define NMCS_PROVIDER_EC2(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMCS_TYPE_PROVIDER_EC2, NMCSProviderEC2))
#define NMCS_PROVIDER_EC2_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMCS_TYPE_PROVIDER_EC2, NMCSProviderEC2Class))
#define NMCS_IS_PROVIDER_EC2(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMCS_TYPE_PROVIDER_EC2))
#define NMCS_IS_PROVIDER_EC2_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMCS_TYPE_PROVIDER_EC2))
#define NMCS_PROVIDER_EC2_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMCS_TYPE_PROVIDER_EC2, NMCSProviderEC2Class))

GType nmcs_provider_ec2_get_type (void);

/*****************************************************************************/

#endif /* __NMCS_PROVIDER_EC2_H__ */
