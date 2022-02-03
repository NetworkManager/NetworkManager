/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "macro.h"

/* Some structures we reference but don't want to pull in headers for */
struct iovec;
struct signalfd_siginfo;

typedef enum LogTarget{
        LOG_TARGET_CONSOLE,
        LOG_TARGET_CONSOLE_PREFIXED,
        LOG_TARGET_KMSG,
        LOG_TARGET_JOURNAL,
        LOG_TARGET_JOURNAL_OR_KMSG,
        LOG_TARGET_SYSLOG,
        LOG_TARGET_SYSLOG_OR_KMSG,
        LOG_TARGET_AUTO, /* console if stderr is not journal, JOURNAL_OR_KMSG otherwise */
        LOG_TARGET_NULL,
        _LOG_TARGET_MAX,
        _LOG_TARGET_INVALID = -EINVAL,
} LogTarget;

/* This log level disables logging completely. It can only be passed to log_set_max_level() and cannot be
 * used a regular log level. */
#define LOG_NULL (LOG_EMERG - 1)

/* Note to readers: << and >> have lower precedence (are evaluated earlier) than & and | */
#define SYNTHETIC_ERRNO(num)                (1 << 30 | (num))
#define IS_SYNTHETIC_ERRNO(val)             ((val) >> 30 & 1)
#define ERRNO_VALUE(val)                    (abs(val) & ~(1 << 30))

/* The callback function to be invoked when syntax warnings are seen
 * in the unit files. */
typedef void (*log_syntax_callback_t)(const char *unit, int level, void *userdata);
void set_log_syntax_callback(log_syntax_callback_t cb, void *userdata);

static inline void clear_log_syntax_callback(dummy_t *dummy) {
          set_log_syntax_callback(/* cb= */ NULL, /* userdata= */ NULL);
}

const char *log_target_to_string(LogTarget target) _const_;
LogTarget log_target_from_string(const char *s) _pure_;
void log_set_target(LogTarget target);
int log_set_target_from_string(const char *e);
LogTarget log_get_target(void) _pure_;

void log_set_max_level(int level);
int log_set_max_level_from_string(const char *e);
#if 0 /* NM_IGNORED */
int log_get_max_level(void) _pure_;
#else /* NM_IGNORED */
static inline int
log_get_max_level(void)
{
        return 7 /* LOG_DEBUG */;
}
#endif /* NM_IGNORED */

void log_set_facility(int facility);

void log_show_color(bool b);
bool log_get_show_color(void) _pure_;
void log_show_location(bool b);
bool log_get_show_location(void) _pure_;
void log_show_time(bool b);
bool log_get_show_time(void) _pure_;
void log_show_tid(bool b);
bool log_get_show_tid(void) _pure_;

int log_show_color_from_string(const char *e);
int log_show_location_from_string(const char *e);
int log_show_time_from_string(const char *e);
int log_show_tid_from_string(const char *e);

/* Functions below that open and close logs or configure logging based on the
 * environment should not be called from library code — this is always a job
 * for the application itself. */

#if 0 /* NM_IGNORED */
assert_cc(STRLEN(__FILE__) > STRLEN(RELATIVE_SOURCE_PATH) + 1);
#define PROJECT_FILE (&__FILE__[STRLEN(RELATIVE_SOURCE_PATH) + 1])
#else /* NM_IGNORED */
#define PROJECT_FILE __FILE__
#endif /* NM_IGNORED */

int log_open(void);
void log_close(void);
void log_forget_fds(void);

void log_parse_environment_variables(void);
void log_parse_environment(void);

#if 0 /* NM_IGNORED */
int log_dispatch_internal(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *object_field,
                const char *object,
                const char *extra,
                const char *extra_field,
                char *buffer);
#endif /* NM_IGNORED */

#if 0 /* NM_IGNORED */
int log_internal(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *format, ...) _printf_(6,7);
#else /* NM_IGNORED */
#define log_internal(level, error, file, line, func, format, ...)                          \
    ({                                                                                     \
        const int        _nm_e = (error);                                                  \
        const NMLogLevel _nm_l = nm_log_level_from_syslog(LOG_PRI(level));                 \
                                                                                           \
        if (_nm_log_enabled_impl(!(NM_THREAD_SAFE_ON_MAIN_THREAD), _nm_l, LOGD_SYSTEMD)) { \
            const char *_nm_location = strrchr(("" file), '/');                            \
                                                                                           \
            _nm_log_full(_nm_location ? _nm_location + 1 : ("" file),                      \
                         (line),                                                           \
                         (func),                                                           \
                         !(NM_THREAD_SAFE_ON_MAIN_THREAD),                                 \
                         _nm_l,                                                            \
                         LOGD_SYSTEMD,                                                     \
                         _nm_e,                                                            \
                         NULL,                                                             \
                         NULL,                                                             \
                         ("%s" format),                                                    \
                         "libsystemd: ",                                                   \
                         ##__VA_ARGS__);                                                   \
        }                                                                                  \
        (_nm_e > 0 ? -_nm_e : _nm_e);                                                      \
    })
#endif /* NM_IGNORED */

#if 0 /* NM_IGNORED */
int log_internalv(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *format,
                va_list ap) _printf_(6,0);

int log_object_internalv(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *object_field,
                const char *object,
                const char *extra_field,
                const char *extra,
                const char *format,
                va_list ap) _printf_(10,0);
#endif /* NM_IGNORED */

#if 0 /* NM_IGNORED */
int log_object_internal(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *object_field,
                const char *object,
                const char *extra_field,
                const char *extra,
                const char *format, ...) _printf_(10,11);
#else /* NM_IGNORED */
#define log_object_internal(level,              \
                            error,              \
                            file,               \
                            line,               \
                            func,               \
                            object_field,       \
                            object,             \
                            extra_field,        \
                            extra,              \
                            format,             \
                            ...)                \
    ({                                          \
        const char *const _object = (object);   \
                                                \
        log_internal((level),                   \
                     (error),                   \
                     file,                      \
                     (line),                    \
                     (func),                    \
                     "%s%s" format,             \
                     _object ?: "",             \
                     _object ? ": " : "",       \
                     ##__VA_ARGS__);            \
    })
#endif /* NM_IGNORED */


#if 0 /* NM_IGNORED */
int log_struct_internal(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *format, ...) _printf_(6,0) _sentinel_;
#endif /* NM_IGNORED */

#if 0 /* NM_IGNORED */
int log_oom_internal(
                int level,
                const char *file,
                int line,
                const char *func);
#else /* NM_IGNORED */
#define log_oom_internal(level, file, line, func) \
    log_internal(level, ENOMEM, file, line, func, "Out of memory.")
#endif /* NM_IGNORED */

#if 0 /* NM_IGNORED */
int log_format_iovec(
                struct iovec *iovec,
                size_t iovec_len,
                size_t *n,
                bool newline_separator,
                int error,
                const char *format,
                va_list ap) _printf_(6, 0);

int log_struct_iovec_internal(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const struct iovec *input_iovec,
                size_t n_input_iovec);

/* This modifies the buffer passed! */
int log_dump_internal(
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                char *buffer);
#endif /* NM_IGNORED */

/* Logging for various assertions */
#if 0 /* NM_IGNORED */
_noreturn_ void log_assert_failed(
                const char *text,
                const char *file,
                int line,
                const char *func);
#else /* NM_IGNORED */
#define log_assert_failed(text, file, line, func)                                \
    G_STMT_START                                                                 \
    {                                                                            \
        log_internal(LOG_CRIT,                                                   \
                     0,                                                          \
                     file,                                                       \
                     line,                                                       \
                     func,                                                       \
                     "Assertion '%s' failed at %s:%u, function %s(). Aborting.", \
                     text,                                                       \
                     file,                                                       \
                     line,                                                       \
                     func);                                                      \
        g_assert_not_reached();                                                  \
    }                                                                            \
    G_STMT_END
#endif /* NM_IGNORED */

#if 0 /* NM_IGNORED */
_noreturn_ void log_assert_failed_unreachable(
                const char *file,
                int line,
                const char *func);
#else /* NM_IGNORED */
#define log_assert_failed_unreachable(file, line, func)                               \
    G_STMT_START                                                                      \
    {                                                                                 \
        log_internal(LOG_CRIT,                                                        \
                     0,                                                               \
                     file,                                                            \
                     line,                                                            \
                     func,                                                            \
                     "Code should not be reached at %s:%u, function %s(). Aborting.", \
                     file,                                                            \
                     line,                                                            \
                     func);                                                           \
        g_assert_not_reached();                                                       \
    }                                                                                 \
    G_STMT_END
#endif /* NM_IGNORED */

#if 0 /* NM_IGNORED */
void log_assert_failed_return(
                const char *text,
                const char *file,
                int line,
                const char *func);
#else /* NM_IGNORED */
#define log_assert_failed_return(text, file, line, func)                         \
    ({                                                                           \
        log_internal(LOG_DEBUG,                                                  \
                     0,                                                          \
                     file,                                                       \
                     line,                                                       \
                     func,                                                       \
                     "Assertion '%s' failed at %s:%u, function %s(). Ignoring.", \
                     text,                                                       \
                     file,                                                       \
                     line,                                                       \
                     func);                                                      \
        g_return_if_fail_warning(G_LOG_DOMAIN, G_STRFUNC, text);                 \
        (void) 0;                                                                \
    })
#endif /* NM_IGNORED */

#if 0 /* NM_IGNORED */
#define log_dispatch(level, error, buffer)                              \
        log_dispatch_internal(level, error, PROJECT_FILE, __LINE__, __func__, NULL, NULL, NULL, NULL, buffer)
#endif /* NM_IGNORED */

/* Logging with level */
#define log_full_errno_zerook(level, error, ...)                        \
        ({                                                              \
                int _level = (level), _e = (error);                     \
                _e = (log_get_max_level() >= LOG_PRI(_level))           \
                        ? log_internal(_level, _e, PROJECT_FILE, __LINE__, __func__, __VA_ARGS__) \
                        : -ERRNO_VALUE(_e);                             \
                _e < 0 ? _e : -ESTRPIPE;                                \
        })

#if BUILD_MODE_DEVELOPER && !defined(TEST_CODE)
#  define ASSERT_NON_ZERO(x) assert((x) != 0)
#else
#  define ASSERT_NON_ZERO(x)
#endif

#define log_full_errno(level, error, ...)                               \
        ({                                                              \
                int _error = (error);                                   \
                ASSERT_NON_ZERO(_error);                                \
                log_full_errno_zerook(level, _error, __VA_ARGS__);      \
        })

#define log_full(level, fmt, ...)                                      \
        ({                                                             \
                if (BUILD_MODE_DEVELOPER)                              \
                        assert(!strstr(fmt, "%m"));                    \
                (void) log_full_errno_zerook(level, 0, fmt, ##__VA_ARGS__); \
        })

int log_emergency_level(void);

/* Normal logging */
#define log_debug(...)     log_full(LOG_DEBUG,   __VA_ARGS__)
#define log_info(...)      log_full(LOG_INFO,    __VA_ARGS__)
#define log_notice(...)    log_full(LOG_NOTICE,  __VA_ARGS__)
#define log_warning(...)   log_full(LOG_WARNING, __VA_ARGS__)
#define log_error(...)     log_full(LOG_ERR,     __VA_ARGS__)
#define log_emergency(...) log_full(log_emergency_level(), __VA_ARGS__)

/* Logging triggered by an errno-like error */
#define log_debug_errno(error, ...)     log_full_errno(LOG_DEBUG,   error, __VA_ARGS__)
#define log_info_errno(error, ...)      log_full_errno(LOG_INFO,    error, __VA_ARGS__)
#define log_notice_errno(error, ...)    log_full_errno(LOG_NOTICE,  error, __VA_ARGS__)
#define log_warning_errno(error, ...)   log_full_errno(LOG_WARNING, error, __VA_ARGS__)
#define log_error_errno(error, ...)     log_full_errno(LOG_ERR,     error, __VA_ARGS__)
#define log_emergency_errno(error, ...) log_full_errno(log_emergency_level(), error, __VA_ARGS__)

/* This logs at the specified level the first time it is called, and then
 * logs at debug. If the specified level is debug, this logs only the first
 * time it is called. */
#define log_once(level, ...)                                             \
        ({                                                               \
                if (ONCE)                                                \
                        log_full(level, __VA_ARGS__);                    \
                else if (LOG_PRI(level) != LOG_DEBUG)                    \
                        log_debug(__VA_ARGS__);                          \
        })

#define log_once_errno(level, error, ...)                                \
        ({                                                               \
                int _err = (error);                                      \
                if (ONCE)                                                \
                        _err = log_full_errno(level, _err, __VA_ARGS__); \
                else if (LOG_PRI(level) != LOG_DEBUG)                    \
                        _err = log_debug_errno(_err, __VA_ARGS__);       \
                else                                                     \
                        _err = -ERRNO_VALUE(_err);                       \
                _err;                                                    \
        })

#if LOG_TRACE
#  define log_trace(...) log_debug(__VA_ARGS__)
#else
#  define log_trace(...) do {} while (0)
#endif

/* Structured logging */
#define log_struct_errno(level, error, ...)                             \
        log_struct_internal(level, error, PROJECT_FILE, __LINE__, __func__, __VA_ARGS__, NULL)
#define log_struct(level, ...) log_struct_errno(level, 0, __VA_ARGS__)

#define log_struct_iovec_errno(level, error, iovec, n_iovec)            \
        log_struct_iovec_internal(level, error, PROJECT_FILE, __LINE__, __func__, iovec, n_iovec)
#define log_struct_iovec(level, iovec, n_iovec) log_struct_iovec_errno(level, 0, iovec, n_iovec)

/* This modifies the buffer passed! */
#define log_dump(level, buffer)                                         \
        log_dump_internal(level, 0, PROJECT_FILE, __LINE__, __func__, buffer)

#define log_oom() log_oom_internal(LOG_ERR, PROJECT_FILE, __LINE__, __func__)
#define log_oom_debug() log_oom_internal(LOG_DEBUG, PROJECT_FILE, __LINE__, __func__)

bool log_on_console(void) _pure_;

/* Helper to prepare various field for structured logging */
#define LOG_MESSAGE(fmt, ...) "MESSAGE=" fmt, ##__VA_ARGS__

void log_received_signal(int level, const struct signalfd_siginfo *si);

/* If turned on, any requests for a log target involving "syslog" will be implicitly upgraded to the equivalent journal target */
void log_set_upgrade_syslog_to_journal(bool b);

/* If turned on, and log_open() is called, we'll not use STDERR_FILENO for logging ever, but rather open /dev/console */
void log_set_always_reopen_console(bool b);

/* If turned on, we'll open the log stream implicitly if needed on each individual log call. This is normally not
 * desired as we want to reuse our logging streams. It is useful however  */
void log_set_open_when_needed(bool b);

/* If turned on, then we'll never use IPC-based logging, i.e. never log to syslog or the journal. We'll only log to
 * stderr, the console or kmsg */
void log_set_prohibit_ipc(bool b);

int log_dup_console(void);

#if 0 /* NM_IGNORED */
int log_syntax_internal(
                const char *unit,
                int level,
                const char *config_file,
                unsigned config_line,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *format, ...) _printf_(9, 10);
#else /* NM_IGNORED */
#define log_syntax_internal(unit, level, config_file, config_line, error, file, line, func, format, ...) \
    log_internal((level), (error), file, (line), (func), "syntax[%s]: "format, (config_file), __VA_ARGS__)
#endif /* NM_IGNORED */

int log_syntax_invalid_utf8_internal(
                const char *unit,
                int level,
                const char *config_file,
                unsigned config_line,
                const char *file,
                int line,
                const char *func,
                const char *rvalue);

#define log_syntax(unit, level, config_file, config_line, error, ...)   \
        ({                                                              \
                int _level = (level), _e = (error);                     \
                (log_get_max_level() >= LOG_PRI(_level))                \
                        ? log_syntax_internal(unit, _level, config_file, config_line, _e, PROJECT_FILE, __LINE__, __func__, __VA_ARGS__) \
                        : -ERRNO_VALUE(_e);                             \
        })

#define log_syntax_invalid_utf8(unit, level, config_file, config_line, rvalue) \
        ({                                                              \
                int _level = (level);                                   \
                (log_get_max_level() >= LOG_PRI(_level))                \
                        ? log_syntax_invalid_utf8_internal(unit, _level, config_file, config_line, PROJECT_FILE, __LINE__, __func__, rvalue) \
                        : -EINVAL;                                      \
        })

#define DEBUG_LOGGING _unlikely_(log_get_max_level() >= LOG_DEBUG)

void log_setup(void);
