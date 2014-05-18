/**
 * keygen.c - Generate and manage symmetric keys. Keys are defined 
 * as arbitrary-length 32-bit word strings. 
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

#include "portable.h"
#include "keygen.h"
#include <stdio.h>
#include <stdlib.h>

/*
 * Generate a symmetric key that is `lKey` 32-bit words long. 
 */
void keygen(uint32_t key[], size_t lKey)
{
  int i;
  for (i = 0; i < lKey; i++) 
  {
    key[i] = u32_LITTLE((uint32_t) rand()); 
  }
}

/*
 * Write a key to file in hexadecimal format. 
 * TODO format checking.
 */
int key_write(const uint32_t key[], size_t lKey, const char *fn)
{
  FILE *fd = fopen(fn, "w"); 
  if (!fd)
    return 0; 
  uint32_t i; 
  for (i = 0; i < lKey; i++) 
  {
    fprintf(fd, "%08X", u32_LITTLE(key[i])); 
    if ((i+1) % 4 == 0) fprintf(fd, "\n"); 
    else fprintf(fd, " "); 
  }
  fclose(fd); 
  return 1; 
}

/*
 * Read a key from file in hexadecimal format. 
 * TODO format checking.
 */
int key_read(uint32_t key[], size_t lKey, const char *fn)
{
  FILE *fd = fopen(fn, "r");
  if (!fd)
    return 0; 
  uint32_t i, input; 
  for (i = 0; i < lKey; i++) 
  {
    fscanf(fd, "%08X", &input); 
    key[i] = u32_LITTLE(input); 
    if ((i+1) % 4 == 0) fscanf(fd, "\n"); 
    else fscanf(fd, " "); 
  }
  fclose(fd); 
  return 1; 
}
