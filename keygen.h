/**
 * keygen.h - Generate and manage symmetric keys. Keys are defined 
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

#ifndef KEYGEN_H
#define KEYGEN_H

#include <stdint.h>
#include <stdlib.h>

void keygen(uint32_t key[], size_t lKey);

int key_write(const uint32_t key[], size_t lKey, const char *fn); 

int key_read(uint32_t key[], size_t lKey, const char *fn); 

#endif // KEYGEN_H
