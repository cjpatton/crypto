/**
 * util.c
 *
 * Copyright (C) 2014, Christopher Patton <chrispatton@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "util.h"
#include <stdio.h>
#include <stdlib.h>

/*
 * Read a line from file, up to `len` or until `delim` is reached. 
 */
int readline(char *buffer, FILE *fd, int len, char delim) 
{
  int i;
  for (i=0; i<len-1; i++) 
  {
    fscanf(fd, "%c", &buffer[i]);
    if (buffer[i] == delim)
      break;
  }
  buffer[i] = '\0';
  return i;
}

/*
 * Convert unsigned long integer to a string in a specified
 * base. Note that `buff` should be at least 64 bytes long.  
 */
char *uitoa(unsigned long n, char *buff, int base)
{
  int i=0;
  char c; 
  while (n > 0)
  {
    buff[i++] = '0' + (char)(n % base); 
    n /= base; 
  }
  buff[i] = '\0';

  base = i - 1; 
  for (i = 0; i <= base/2; i++)
  {
    c = buff[i]; 
    buff[i] = buff[base-i]; 
    buff[base-i] = c;
  }

  return buff;  
}

