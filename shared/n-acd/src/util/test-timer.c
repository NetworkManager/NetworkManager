/*
 * Tests for timer utility library
 */

#undef NDEBUG
#include <c-stdaux.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/timerfd.h>
#include "timer.h"

#define N_TIMEOUTS (10000)

static void test_api(void) {
        Timer timer = TIMER_NULL(timer);
        Timeout t1 = TIMEOUT_INIT(t1), t2 = TIMEOUT_INIT(t2), *t;
        int r;

        r = timer_init(&timer);
        c_assert(!r);

        timeout_schedule(&t1, &timer, 1);
        timeout_schedule(&t2, &timer, 2);

        r = timer_pop_timeout(&timer, 10, &t);
        c_assert(!r);
        c_assert(t == &t1);

        timeout_unschedule(&t2);

        r = timer_pop_timeout(&timer, 10, &t);
        c_assert(!r);
        c_assert(!t);

        timer_deinit(&timer);
}

static void test_pop(void) {
        Timer timer = TIMER_NULL(timer);
        Timeout timeouts[N_TIMEOUTS] = {};
        uint64_t times[N_TIMEOUTS] = {};
        size_t n_timeouts = 0;
        bool armed;
        Timeout *t;
        int r;

        r = timer_init(&timer);
        c_assert(!r);

        for(size_t i = 0; i < N_TIMEOUTS; ++i) {
                timeouts[i] = (Timeout)TIMEOUT_INIT(timeouts[i]);
                times[i] = rand() % 128 + 1;
                timeout_schedule(&timeouts[i], &timer, times[i]);
        }

        armed = true;

        for(size_t i = 0; i <= 128; ++i) {
                if (armed) {
                        struct pollfd pfd = {
                                .fd = timer.fd,
                                .events = POLLIN,
                        };
                        uint64_t count;

                        r = poll(&pfd, 1, -1);
                        c_assert(r == 1);

                        r = read(timer.fd, &count, sizeof(count));
                        c_assert(r == sizeof(count));
                        c_assert(count == 1);
                        armed = false;
                }

                for (;;) {
                        uint64_t current_time;

                        r = timer_pop_timeout(&timer, i, &t);
                        c_assert(!r);
                        if (!t) {
                                timer_rearm(&timer);
                                break;
                        }

                        current_time = times[t - timeouts];
                        c_assert(current_time == i);
                        ++n_timeouts;
                        armed = true;
                }
        }

        c_assert(n_timeouts == N_TIMEOUTS);

        r = timer_pop_timeout(&timer, (uint64_t)-1, &t);
        c_assert(!r);
        c_assert(!t);

        timer_deinit(&timer);
}

void test_arm(void) {
        struct itimerspec spec = {
                .it_value = {
                        .tv_sec = 1000,
                },
        };
        int fd1, fd2, r;

        fd1 = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
        c_assert(fd1 >= 0);

        fd2 = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
        c_assert(fd1 >= 0);

        r = timerfd_settime(fd1, 0, &spec, NULL);
        c_assert(r >= 0);

        r = timerfd_settime(fd2, 0, &spec, NULL);
        c_assert(r >= 0);

        r = timerfd_gettime(fd1, &spec);
        c_assert(r >= 0);
        c_assert(spec.it_value.tv_sec);

        r = timerfd_gettime(fd2, &spec);
        c_assert(r >= 0);
        c_assert(spec.it_value.tv_sec);

        spec = (struct itimerspec){};

        r = timerfd_settime(fd1, 0, &spec, NULL);
        c_assert(r >= 0);

        r = timerfd_gettime(fd1, &spec);
        c_assert(r >= 0);
        c_assert(!spec.it_value.tv_sec);
        c_assert(!spec.it_value.tv_nsec);

        r = timerfd_gettime(fd2, &spec);
        c_assert(r >= 0);
        c_assert(spec.it_value.tv_sec);

        spec = (struct itimerspec){ .it_value = { .tv_nsec = 1, }, };

        r = timerfd_settime(fd1, 0, &spec, NULL);
        c_assert(r >= 0);

        r = poll(&(struct pollfd) { .fd = fd1, .events = POLLIN }, 1, -1);
        c_assert(r == 1);

        r = timerfd_settime(fd2, 0, &spec, NULL);
        c_assert(r >= 0);

        r = poll(&(struct pollfd) { .fd = fd2, .events = POLLIN }, 1, -1);
        c_assert(r == 1);

        spec = (struct itimerspec){};

        r = timerfd_settime(fd1, 0, &spec, NULL);
        c_assert(r >= 0);

        r = poll(&(struct pollfd) { .fd = fd2, .events = POLLIN }, 1, -1);
        c_assert(r == 1);

        close(fd2);
        close(fd1);
}

int main(int argc, char **argv) {
        test_arm();
        test_api();
        test_pop();
        return 0;
}
