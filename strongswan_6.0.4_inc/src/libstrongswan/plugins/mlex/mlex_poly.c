/*
 * Copyright (C) 2024 Tobias Brunner
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

#include "mlex_poly.h"
#include "mlex_utils.h"

/*
 * Described in header
 */
void mlex_poly_add(mlex_poly_t *a, mlex_poly_t *b, mlex_poly_t *res)
{
	int i;

	for (i = 0; i < ML_KEM_N; i++)
	{
		res->f[i] = mlex_reduce_modq(a->f[i] + b->f[i]);
	}
}

/*
 * Described in header
 */
void mlex_poly_add_arr(u_int k, mlex_poly_t *a, mlex_poly_t *b, mlex_poly_t *res)
{
	while (k--)
	{
		mlex_poly_add(&a[k], &b[k], &res[k]);
	}
}

/*
 * Described in header
 */
void mlex_poly_sub(mlex_poly_t *a, mlex_poly_t *b, mlex_poly_t *res)
{
	int i;

	for (i = 0; i < ML_KEM_N; i++)
	{
		res->f[i] = mlex_reduce_modq(a->f[i] - b->f[i] + ML_KEM_Q);
	}
}

