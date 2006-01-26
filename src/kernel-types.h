#ifndef _KERNEL_TYPES_H
#define _KERNEL_TYPES_H

/*
 * Various headers leak the kernel-only types u16, u32, et al.  User-space
 * does not supply these types, so we define them here.
 */

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;
typedef __s64 s64;
typedef __s32 s32;
typedef __s16 s16;
typedef __s8 s8;

#endif	/* _KERNEL_TYPES_H */
