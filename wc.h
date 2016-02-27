/*
 * This source code is a modified version of the wc source example at: 
 * https://www.gnu.org/software/cflow/manual/html_node/Source-of-wc-command.html
 *
 * Copyright (C) Chiron Technology Inc.
 *
 * This program is free software; you can redistribute it and/or modify it under 
 * the terms of the GNU General Public License as published by the Free Software 
 * Foundation; either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with 
 * this program; if not, see <http://www.gnu.org/licenses>.
 *
 * Additional permission under GNU GPL version 3 section 7
 *
 */

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#define COUNT(c)       \
      ccount++;        \
      if ((c) == '\n') \
        lcount++;

typedef unsigned long count_t; /* Counter type */
static void error_print(int perr, char *fmt, va_list ap);
static void perrf (char *fmt, ...);
void report (char *file, count_t ccount, count_t wcount, count_t lcount);
static int isword (unsigned char c);
int getword (FILE *fp);
void counter (char *file);
int reportTotal (char * argv);
