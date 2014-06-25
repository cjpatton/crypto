/**
 * portable.h - Routines for making sure that things run smoothly 
 * across platforms. I would like to support direclty casting a 
 * (char *) type to a (uint32_t *). 
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

#ifndef PORTABLE_H
#define PORTABLE_H 

#include <stdint.h>
#include <arpa/inet.h>

/* TODO generic little endian conversion for u32 and u64. Operate on a
 * byte array. */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define u32_LITTLE(x) x
#else 
#define u32_LITTLE(x) x /* FIXME */
#endif 

/* TODO Rotate left/right instructions, using the one defined
 * in aex.c for x86 architecture. */ 

#endif // PORTABLE_H
