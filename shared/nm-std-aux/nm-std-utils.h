/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_STD_UTILS_H__
#define __NM_STD_UTILS_H__

#include <stdbool.h>

#include "nm-std-aux.h"

/*****************************************************************************/

/* nm_utils_get_next_realloc_size() is used to grow buffers exponentially, when
 * the final size is unknown. As such, it has borders for which it allocates
 * certain buffer sizes.
 *
 * The use of these defines is to get favorable allocation sequences.
 * For example, nm_str_buf_init() asks for an initial allocation size. Note that
 * it reserves the exactly requested amount, under the assumption that the
 * user may know how many bytes will be required. However, often the caller
 * doesn't know in advance, and NMStrBuf grows exponentially by calling
 * nm_utils_get_next_realloc_size().
 * Imagine you call nm_str_buf_init() with an initial buffer size 100, and you
 * add one character at a time. Then the first reallocation will increase the
 * buffer size only from 100 to 104.
 * If you however start with an initial buffer size of 104, then the next reallocation
 * via nm_utils_get_next_realloc_size() gives you 232, and so on. By using
 * these sizes, it results in one less allocation, if you anyway don't know the
 * exact size in advance. */
#define NM_UTILS_GET_NEXT_REALLOC_SIZE_32   ((size_t) 32)
#define NM_UTILS_GET_NEXT_REALLOC_SIZE_40   ((size_t) 40)
#define NM_UTILS_GET_NEXT_REALLOC_SIZE_104  ((size_t) 104)
#define NM_UTILS_GET_NEXT_REALLOC_SIZE_1000 ((size_t) 1000)

size_t nm_utils_get_next_realloc_size(bool true_realloc, size_t requested);

#endif /* __NM_STD_UTILS_H__ */
