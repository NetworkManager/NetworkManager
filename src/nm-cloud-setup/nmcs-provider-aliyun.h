/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NMCS_PROVIDER_ALIYUN_H__
#define __NMCS_PROVIDER_ALIYUN_H__

#include "nmcs-provider.h"

/*****************************************************************************/

typedef struct _NMCSProviderAliyun      NMCSProviderAliyun;
typedef struct _NMCSProviderAliyunClass NMCSProviderAliyunClass;

#define NMCS_TYPE_PROVIDER_ALIYUN (nmcs_provider_aliyun_get_type())
#define NMCS_PROVIDER_ALIYUN(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NMCS_TYPE_PROVIDER_ALIYUN, NMCSProviderAliyun))
#define NMCS_PROVIDER_ALIYUN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMCS_TYPE_PROVIDER_ALIYUN, NMCSProviderAliyunClass))
#define NMCS_IS_PROVIDER_ALIYUN(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMCS_TYPE_PROVIDER_ALIYUN))
#define NMCS_IS_PROVIDER_ALIYUN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NMCS_TYPE_PROVIDER_ALIYUN))
#define NMCS_PROVIDER_ALIYUN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMCS_TYPE_PROVIDER_ALIYUN, NMCSProviderAliyunClass))

GType nmcs_provider_aliyun_get_type(void);

/*****************************************************************************/

#endif /* __NMCS_PROVIDER_ALIYUN_H__ */
