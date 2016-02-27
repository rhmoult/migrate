#include "wc.h"

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

typedef unsigned long count_t; /* Counter type */

count_t ccount;
count_t wcount;
count_t lcount;

count_t total_ccount = 0;
count_t total_wcount = 0;
count_t total_lcount = 0;

static void error_print(int perr, char *fmt, va_list ap)
{
    vfprintf(stderr, fmt, ap);
    if(perr)
        perror(" ");
    else
        fprintf(stderr, "\n");
    exit(1);
}

     
/* Print error message followed by errno status and exit
        with error code. */
static void perrf (char *fmt, ...)
{ 
    va_list ap; 
    va_start (ap, fmt);
    error_print (1, fmt, ap);
    va_end (ap); 
}
     
/* Output counters for given file */
void report (char *file, count_t ccount, count_t wcount, count_t lcount)
{
    //printf ("%6lu\n", ccount);
}
     
/* Return true if C is a valid word constituent */
static int isword (unsigned char c)
  {
    return isalpha (c);
  }
     
     
/* Get next word from the input stream. Return 0 on end
   of file or error condition. Return 1 otherwise. */
int getword (FILE *fp)
{
    int c;
     
    if (feof (fp))
      return 0;
           
    while ((c = getc (fp)) != EOF)
      {
        if (isword (c))
          {
            wcount++;
            break;
          }
        COUNT (c);
      }
  
    for (; c != EOF; c = getc (fp))
      {
        COUNT (c);
        if (!isword (c))
          break;
      }
  
    return c != EOF;
}
         
/* Process file FILE. */
void counter (char *file)
{
    FILE *fp = fopen (file, "r");
       
    if (!fp)
      perrf ("cannot open file `%s'", file);
     
    ccount = wcount = lcount = 0;
    while (getword (fp))
      ;
    fclose (fp);
     
    report (file, ccount, wcount, lcount);
    total_ccount += ccount;
    total_wcount += wcount;
    total_lcount += lcount;
}
       
int reportTotal (char * argv)
{
    counter (argv);
   
    //report ("total", total_ccount, total_wcount, total_lcount);
    return total_ccount;
}
