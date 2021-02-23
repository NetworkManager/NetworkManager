/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "time-util.h"
#include "util.h"

typedef struct RateLimit {
        usec_t interval; /* Keep those two fields first so they can be initialized easily: */
        unsigned burst;  /*   RateLimit rl = { INTERVAL, BURST }; */
        unsigned num;
        usec_t begin;
} RateLimit;

static inline void ratelimit_reset(RateLimit *rl) {
        rl->num = rl->begin = 0;
}

static inline bool ratelimit_configured(RateLimit *rl) {
        return rl->interval > 0 && rl->burst > 0;
}

bool ratelimit_below(RateLimit *r);
