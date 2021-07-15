# ===========================================================================
#     https://www.gnu.org/software/autoconf-archive/ax_lib_readline.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_LIB_READLINE
#
# DESCRIPTION
#
#   Searches for a readline compatible library. If found, defines
#   `HAVE_LIBREADLINE'. If the found library has the `add_history' function,
#   sets also `HAVE_READLINE_HISTORY'. Also checks for the locations of the
#   necessary include files and sets `HAVE_READLINE_H' or
#   `HAVE_READLINE_READLINE_H' and `HAVE_READLINE_HISTORY_H' or
#   'HAVE_HISTORY_H' if the corresponding include files exists.
#
#   The libraries that may be readline compatible are `libedit',
#   `libeditline' and `libreadline'. Sometimes we need to link a termcap
#   library for readline to work, this macro tests these cases too by trying
#   to link with `libtermcap', `libcurses' or `libncurses' before giving up.
#
#   Here is an example of how to use the information provided by this macro
#   to perform the necessary includes or declarations in a C file:
#
#     #ifdef HAVE_LIBREADLINE
#     #  if defined(HAVE_READLINE_READLINE_H)
#     #    include <readline/readline.h>
#     #  elif defined(HAVE_READLINE_H)
#     #    include <readline.h>
#     #  else /* !defined(HAVE_READLINE_H) */
#     extern char *readline ();
#     #  endif /* !defined(HAVE_READLINE_H) */
#     char *cmdline = NULL;
#     #else /* !defined(HAVE_READLINE_READLINE_H) */
#       /* no readline */
#     #endif /* HAVE_LIBREADLINE */
#
#     #ifdef HAVE_READLINE_HISTORY
#     #  if defined(HAVE_READLINE_HISTORY_H)
#     #    include <readline/history.h>
#     #  elif defined(HAVE_HISTORY_H)
#     #    include <history.h>
#     #  else /* !defined(HAVE_HISTORY_H) */
#     extern void add_history ();
#     extern int write_history ();
#     extern int read_history ();
#     #  endif /* defined(HAVE_READLINE_HISTORY_H) */
#       /* no history */
#     #endif /* HAVE_READLINE_HISTORY */
#
# LICENSE
#
#   Copyright (c) 2008 Ville Laurikari <vl@iki.fi>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 8

AU_ALIAS([VL_LIB_READLINE], [AX_LIB_READLINE])
AC_DEFUN([AX_LIB_READLINE], [

  AC_ARG_WITH(readline,
              AS_HELP_STRING([--with-readline=auto|libreadline|libedit|none], [Using libreadline (auto) or libedit]),
              [],
              [with_readline=auto])

  if test "$with_readline" != "none"; then

    AC_CACHE_CHECK([for a readline compatible library],
                   ax_cv_lib_readline, [
      ORIG_LIBS="$LIBS"

      if test "$with_readline" = "libreadline"; then
        search_readlines="readline"
      elif test "$with_readline" = "libedit"; then
        search_readlines="edit"
      elif test "$with_readline" = "auto"; then
        search_readlines="readline edit"
      else
        AC_MSG_ERROR([invalid --with-readline option. Valid options are --with-readline=auto|libreadline|libedit|none])
      fi

      for readline_lib in $search_readlines; do
        # prefer ncurses since we use it for nmtui too
        for termcap_lib in "" termcap curses ncurses; do
          if test -z "$termcap_lib"; then
            TRY_LIB="-l$readline_lib"
          else
            TRY_LIB="-l$readline_lib -l$termcap_lib"
          fi
          LIBS="$ORIG_LIBS $TRY_LIB"
          AC_LINK_IFELSE([AC_LANG_CALL([], [readline])], [ax_cv_lib_readline="$TRY_LIB"])
          if test -n "$ax_cv_lib_readline"; then
            break
          fi
        done
        if test -n "$ax_cv_lib_readline"; then
          if test "$with_readline" = auto; then
            if test "$readline_lib" = readline; then
              with_readline=libreadline
            else
              with_readline=libedit
            fi
          fi
          break
        fi
      done
      if test -z "$ax_cv_lib_readline"; then
        if test "$with_readline" != auto; then
          AC_MSG_ERROR([libreadline not found for --with-readline=$with_readline"])
        fi
        with_readline=none
        ax_cv_lib_readline="no"
      fi
      LIBS="$ORIG_LIBS"
    ])

    if test "$ax_cv_lib_readline" != "no"; then
      READLINE_LIBS="$ax_cv_lib_readline"
      AC_SUBST(READLINE_LIBS)
      AC_DEFINE(HAVE_LIBREADLINE, 1,
                [Define if you have a readline compatible library])

      if test "$with_readline" = "libedit"; then
        AC_DEFINE(HAVE_EDITLINE_READLINE, 1,
                [Explicitly set to 1 when libedit shall be used])
      else
        AC_DEFINE(HAVE_EDITLINE_READLINE, 0,
                [By default the libreadline is used as readline library])

      fi

      ORIG_LIBS="$LIBS"
      LIBS="$ORIG_LIBS $ax_cv_lib_readline"
      AC_CACHE_CHECK([whether readline supports history],
                     ax_cv_lib_readline_history, [
        ax_cv_lib_readline_history="no"
        AC_LINK_IFELSE([AC_LANG_CALL([], [history_set_history_state])],
                [ax_cv_lib_readline_history="yes"])
      ])
      LIBS=$ORIG_LIBS

      if test "$ax_cv_lib_readline_history" = "yes"; then
        AC_DEFINE(HAVE_READLINE_HISTORY, 1,
          [Define if your readline library has \`history_set_history_state'])
        AC_CHECK_HEADERS(readline/history.h histedit.h)
      else
        AC_DEFINE(HAVE_READLINE_HISTORY, 0,
          [Explicitly set to 0 when libreadline shall not be used])
      fi
    fi

  fi
])dnl
