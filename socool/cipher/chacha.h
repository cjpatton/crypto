/**
 * chacha.h - Header for the 512-bit ChaCha streamcipher, invented by 
 * Daniel Bernstein (http://cr.yp.to/chacha.html).
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

#ifndef CHACHA_H
#define CHACHA_H

#include <stdint.h>
#include <stdlib.h>

#define CHA_BLOCK     512
#define CHA_BLOCK_u8  512 / 8 
#define CHA_BLOCK_u32 512 / 32

void chacha_disp_state(const uint32_t X[16]); 

void chacha_set_iv(uint32_t iv[4], long n, long l);

void chacha_init(uint32_t X[16], 
                 const uint32_t key[8], 
                 const uint32_t iv[4]); 

void chacha16(uint32_t out[16], const uint32_t X[16]); 

void chacha_blockcipher(char *out, const char *in, 
                        const uint32_t key[8], 
                        uint64_t n, uint64_t l); 

void chacha_streamcipher(char *out, const char *in, size_t bytes, 
                         const uint32_t key[8], 
                         uint64_t n, uint64_t l); 

#endif // CHACHA_H 
