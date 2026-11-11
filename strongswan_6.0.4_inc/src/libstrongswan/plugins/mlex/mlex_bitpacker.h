/*
 * Copyright (C) 2024 Tobias Brunner
 * Copyright (C) 2014 Andreas Steffen
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup mlex_bitpacker mlex_bitpacker
 * @{ @ingroup mlex_p
 */

#ifndef mlex_BITPACKER_H_
#define mlex_BITPACKER_H_

#include <library.h>

typedef struct mlex_bitpacker_t mlex_bitpacker_t;

/**
 * Reads and writes a variable number of bits in packed format
 * from and to an octet buffer.
 */
struct mlex_bitpacker_t {

	/**
	 * Write a number of bits of the given value to the buffer.
	 *
	 * @param value		value to be written
	 * @param bits		number of bits to be written
	 * @result			TRUE if value could be written into buffer
	 */
	bool (*write_bits)(mlex_bitpacker_t *this, uint32_t value, size_t bits);

	/**
	 * Get a number of bits from the buffer.
	 *
	 * @param value		read value
	 * @param bits		number of bits to be read
	 * @result			TRUE if value could be read from buffer
	 */
	bool (*read_bits)(mlex_bitpacker_t *this, uint32_t *value, size_t bits);

	/**
	 * Destroy the object.
	 *
	 * Note that when writing, this flushes the internal buffer and writes the
	 * remaining bits if there is still room in the destination buffer.
	 */
	void (*destroy)(mlex_bitpacker_t *this);
};

/**
 * Create a mlex_bitpacker_t object for writing to a buffer.
 *
 * @param dst			existing buffer to write bits to
 */
mlex_bitpacker_t *mlex_bitpacker_create(chunk_t dst);

/**
 * Create a mlex_bitpacker_t object for reading.
 *
 * @param data			packed array of bits
 */
mlex_bitpacker_t *mlex_bitpacker_create_from_data(chunk_t data);

#endif /** mlex_BITPACKER_H_ @}*/

