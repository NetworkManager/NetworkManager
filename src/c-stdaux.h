#pragma once

/*
 * c-stdaux: Auxiliary macros and functions for the C standard library
 *
 * Main public header of the c-stdaux library. All includes of this header are
 * part of the API!
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * DOC:
 *
 * The ``c-stdaux.h`` header contains a collection of auxiliary macros and
 * helper functions around the functionality provided by the different C
 * standard library implementations, as well as other specifications
 * implemented by them.
 *
 * Most of the helpers provided here provide aliases for common library and
 * compiler features. Furthermore, several helpers simply provide other calling
 * conventions than their standard counterparts (e.g., they allow for NULL to
 * be passed with an object length of 0 where it makes sense to accept empty
 * input).
 *
 * The namespace used by this project is:
 *
 * -  ``c_*`` for all common C symbols or definitions that behave like proper C
 *    entities (e.g., macros that protect against double-evaluation would use
 *    lower-case names).
 *
 * -  ``C_*`` for all constants, as well as macros that may not be safe against
 *    double evaluation.
 *
 * -  ``c_internal_*`` and ``C_INTERNAL_*`` for all internal symbols that
 *    should not be invoked by the caller and are not part of the API
 *    guarantees.
 */
/**/

#include <c-stdaux-generic.h>

#if defined(C_COMPILER_GNUC)
#  include <c-stdaux-gnuc.h>
#endif

#if defined(C_OS_LINUX) || defined(C_OS_MACOS)
#  include <c-stdaux-unix.h>
#endif

#ifdef __cplusplus
}
#endif
