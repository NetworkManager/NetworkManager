/*
 * shvar.c
 *
 * Implementation of non-destructively reading/writing files containing
 * only shell variable declarations and full-line comments.
 *
 * Includes explicit inheritance mechanism intended for use with
 * Red Hat Linux ifcfg-* files.  There is no protection against
 * inheritance loops; they will generally cause stack overflows.
 * Furthermore, they are only intended for one level of inheritance;
 * the value setting algorithm assumes this.
 *
 * Copyright 1999,2000 Red Hat, Inc.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shvar.h"

/* Open the file <name>, returning a shvarFile on success and NULL on failure.
   Add a wrinkle to let the caller specify whether or not to create the file
   (actually, return a structure anyway) if it doesn't exist. */
static shvarFile *
svOpenFile(const char *name, gboolean create)
{
    shvarFile *s = NULL;
    int closefd = 0;

    s = g_malloc0(sizeof(shvarFile));

    s->fd = -1;
    if (create)
	s->fd = open(name, O_RDWR); /* NOT O_CREAT */
 
    if (!create || s->fd == -1) {
	/* try read-only */
	s->fd = open(name, O_RDONLY); /* NOT O_CREAT */
	if (s->fd != -1) closefd = 1;
    }
    s->fileName = g_strdup(name);

    if (s->fd != -1) {
	struct stat buf;
	char *p, *q;

	if (fstat(s->fd, &buf) < 0) goto bail;
	s->arena = g_malloc0(buf.st_size + 1);

	if (read(s->fd, s->arena, buf.st_size) < 0) goto bail;

	/* we'd use g_strsplit() here, but we want a list, not an array */
	for(p = s->arena; (q = strchr(p, '\n')) != NULL; p = q + 1) {
		s->lineList = g_list_append(s->lineList, g_strndup(p, q - p));
	}

	/* closefd is set if we opened the file read-only, so go ahead and
	   close it, because we can't write to it anyway */
	if (closefd) {
	    close(s->fd);
	    s->fd = -1;
	}

        return s;
    }

    if (create) {
        return s;
    }

bail:
    if (s->fd != -1) close(s->fd);
    if (s->arena) g_free (s->arena);
    if (s->fileName) g_free (s->fileName);
    g_free (s);
    return NULL;
}

/* Open the file <name>, return shvarFile on success, NULL on failure */
shvarFile *
svNewFile(const char *name)
{
    return svOpenFile(name, FALSE);
}

/* Create a new file structure, returning actual data if the file exists,
 * and a suitable starting point if it doesn't. */
shvarFile *
svCreateFile(const char *name)
{
    return svOpenFile(name, TRUE);
}

/* remove escaped characters in place */
void
svUnescape(char *s) {
    int len, i;

    len = strlen(s);
    if ((s[0] == '"' || s[0] == '\'') && s[0] == s[len-1]) {
	i = len - 2;
	if (i == 0)
	  s[0] = '\0';
	else {
	  memmove(s, s+1, i);
	  s[i+1] = '\0';
	  len = i;
	}
    }
    for (i = 0; i < len; i++) {
	if (s[i] == '\\') {
	    memmove(s+i, s+i+1, len-(i+1));
	    len--;
	}
	s[len] = '\0';
    }
}


/* create a new string with all necessary characters escaped.
 * caller must free returned string
 */
static const char escapees[] = "\"'\\$~`";		/* must be escaped */
static const char spaces[] = " \t|&;()<>";		/* only require "" */
char *
svEscape(const char *s) {
    char *new;
    int i, j, mangle = 0, space = 0;
    int newlen, slen;
    static int esclen, splen;

    if (!esclen) esclen = strlen(escapees);
    if (!splen) splen = strlen(spaces);
    slen = strlen(s);

    for (i = 0; i < slen; i++) {
	if (strchr(escapees, s[i])) mangle++;
	if (strchr(spaces, s[i])) space++;
    }
    if (!mangle && !space) return strdup(s);

    newlen = slen + mangle + 3;	/* 3 is extra ""\0 */
    new = g_malloc0(newlen);
    if (!new) return NULL;

    j = 0;
    new[j++] = '"';
    for (i = 0; i < slen; i++) {
	if (strchr(escapees, s[i])) {
	    new[j++] = '\\';
	}
	new[j++] = s[i];
    }
    new[j++] = '"';
    g_assert(j == slen + mangle + 2); /* j is the index of the '\0' */

    return new;
}

/* Get the value associated with the key, and leave the current pointer
 * pointing at the line containing the value.  The char* returned MUST
 * be freed by the caller.
 */
char *
svGetValue(shvarFile *s, const char *key, gboolean verbatim)
{
    char *value = NULL;
    char *line;
    char *keyString;
    int len;

    g_assert(s);
    g_assert(key);

    keyString = g_malloc0(strlen(key) + 2);
    strcpy(keyString, key);
    keyString[strlen(key)] = '=';
    len = strlen(keyString);

    for (s->current = s->lineList; s->current; s->current = s->current->next) {
	line = s->current->data;
	if (!strncmp(keyString, line, len)) {
	    value = g_strdup(line + len);
	    if (!verbatim)
	      svUnescape(value);
	    break;
	}
    }
    g_free(keyString);

    if (value) {
	if (value[0]) {
	    return value;
	} else {
	    g_free(value);
	    return NULL;
	}
    }
    if (s->parent) value = svGetValue(s->parent, key, verbatim);
    return value;
}

/* return 1 if <key> resolves to any truth value (e.g. "yes", "y", "true")
 * return 0 if <key> resolves to any non-truth value (e.g. "no", "n", "false")
 * return <default> otherwise
 */
int
svTrueValue(shvarFile *s, const char *key, int def)
{
    char *tmp;
    int returnValue = def;

    tmp = svGetValue(s, key, FALSE);
    if (!tmp) return returnValue;

    if ( (!strcasecmp("yes", tmp)) ||
	 (!strcasecmp("true", tmp)) ||
	 (!strcasecmp("t", tmp)) ||
	 (!strcasecmp("y", tmp)) ) returnValue = 1;
    else
    if ( (!strcasecmp("no", tmp)) ||
	 (!strcasecmp("false", tmp)) ||
	 (!strcasecmp("f", tmp)) ||
	 (!strcasecmp("n", tmp)) ) returnValue = 0;

    g_free (tmp);
    return returnValue;
}


/* Set the variable <key> equal to the value <value>.
 * If <key> does not exist, and the <current> pointer is set, append
 * the key=value pair after that line.  Otherwise, prepend the pair
 * to the top of the file.  Here's the algorithm, as the C code
 * seems to be rather dense:
 *
 * if (value == NULL), then:
 *     if val2 (parent): change line to key= or append line key=
 *     if val1 (this)  : delete line
 *     else noop
 * else use this table:
 *                                val2
 *             NULL              value               other
 * v   NULL    append line       noop                append line
 * a
 * l   value   noop              noop                noop
 * 1
 *     other   change line       delete line         change line
 *
 * No changes are ever made to the parent config file, only to the
 * specific file passed on the command line.
 *
 */
void
svSetValue(shvarFile *s, const char *key, const char *value, gboolean verbatim)
{
    char *newval = NULL, *val1 = NULL, *val2 = NULL;
    char *keyValue;

    g_assert(s);
    g_assert(key);
    /* value may be NULL */

    if (value)
        newval = verbatim ? g_strdup(value) : svEscape(value);
    keyValue = g_strdup_printf("%s=%s", key, newval ? newval : "");

    val1 = svGetValue(s, key, FALSE);
    if (val1 && newval && !strcmp(val1, newval)) goto bail;
    if (s->parent) val2 = svGetValue(s->parent, key, FALSE);

    if (!newval || !newval[0]) {
	/* delete value somehow */
	if (val2) {
	    /* change/append line to get key= */
	    if (s->current) s->current->data = keyValue;
	    else s->lineList = g_list_append(s->lineList, keyValue);
	    s->modified = 1;
	} else if (val1) {
	    /* delete line */
	    s->lineList = g_list_remove_link(s->lineList, s->current);
	    g_list_free_1(s->current);
	    s->modified = 1;
	    goto bail; /* do not need keyValue */
	}
	goto end;
    }

    if (!val1) {
	if (val2 && !strcmp(val2, newval)) goto end;
	/* append line */
	s->lineList = g_list_append(s->lineList, keyValue);
	s->modified = 1;
	goto end;
    }

    /* deal with a whole line of noops */
    if (val1 && !strcmp(val1, newval)) goto end;

    /* At this point, val1 && val1 != value */
    if (val2 && !strcmp(val2, newval)) {
	/* delete line */
	s->lineList = g_list_remove_link(s->lineList, s->current);
	g_list_free_1(s->current);
	s->modified = 1;
	goto bail; /* do not need keyValue */
    } else {
	/* change line */
	if (s->current) s->current->data = keyValue;
	else s->lineList = g_list_append(s->lineList, keyValue);
	s->modified = 1;
    }

end:
    if (newval) free(newval);
    if (val1) free(val1);
    if (val2) free(val2);
    return;

bail:
    if (keyValue) free (keyValue);
    goto end;
}

/* Write the current contents iff modified.  Returns -1 on error
 * and 0 on success.  Do not write if no values have been modified.
 * The mode argument is only used if creating the file, not if
 * re-writing an existing file, and is passed unchanged to the
 * open() syscall.
 */
int
svWriteFile(shvarFile *s, int mode)
{
    FILE *f;
    int tmpfd;

    if (s->modified) {
	if (s->fd == -1)
	    s->fd = open(s->fileName, O_WRONLY|O_CREAT, mode);
	if (s->fd == -1)
	    return -1;
	if (ftruncate(s->fd, 0) < 0)
	    return -1;

	tmpfd = dup(s->fd);
	f = fdopen(tmpfd, "w");
	fseek(f, 0, SEEK_SET);
	for (s->current = s->lineList; s->current; s->current = s->current->next) {
	    char *line = s->current->data;
	    fprintf(f, "%s\n", line);
	}
	fclose(f);
    }

    return 0;
}

 
/* Close the file descriptor (if open) and delete the shvarFile.
 * Returns -1 on error and 0 on success.
 */
int
svCloseFile(shvarFile *s)
{

    g_assert(s);

    if (s->fd != -1) close(s->fd);

    g_free(s->arena);
    g_free(s->fileName);
    g_list_foreach (s->lineList, (GFunc) g_free, NULL);
    g_list_free(s->lineList); /* implicitly frees s->current */
    g_free(s);
    return 0;
}
