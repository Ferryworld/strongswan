/*
 * Copyright (C) 2016 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "newhope_ke.h"

#include <crypto/diffie_hellman.h>
#include <utils/debug.h>

static const int seed_len = 32;		/* 256 bits */
static const int n = 1024;			/* rank of ring */
static const uint16_t q = 12289;	/* prime modulus */

typedef struct private_newhope_ke_t private_newhope_ke_t;

/**
 * Private data of an newhope_ke_t object.
 */
struct private_newhope_ke_t {
	/**
	 * Public newhope_ke_t interface.
	 */
	newhope_ke_t public;

};

METHOD(diffie_hellman_t, get_my_public_value, bool,
	private_newhope_ke_t *this, chunk_t *value)
{
	rng_t *rng;
	xof_t *xof = NULL;
	chunk_t seed = chunk_empty;
	bool success = FALSE;
	uint16_t a[n];
	uint8_t x[2];
	int i = 0;

	rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (!rng)
	{
		DBG1(DBG_LIB, "could not instatiate random source");
		return FALSE;
	}
	if (!rng->allocate_bytes(rng, seed_len, &seed))
	{
		DBG1(DBG_LIB, "could not generate seed");
		goto end;
	}

	xof = lib->crypto->create_xof(lib->crypto, XOF_SHAKE_128);
	if (!xof)
	{
		DBG1(DBG_LIB, "could not instantiate SHAKE128 XOF");
		goto end;
	}

	if (!xof->set_seed(xof, seed))
	{
		DBG1(DBG_LIB, "could not set seed of SHAKE128 XOF");
		goto end;
	}

	while (i < n)
	{
		if (!xof->get_bytes(xof, sizeof(x), x))
		{
			DBG1(DBG_LIB, "could not get bytes from SHAKE128 XOF");
			goto end;
		}

		/* Treat x as a 16 bit unsigned little endian integer */
		a[i] = (x[0] + (x[1] << 8)) & 0x3fff;

		if (a[i] < q)
		{
			i++;
		}
	}
	success = TRUE;

end:
	DESTROY_IF(xof);
	DESTROY_IF(rng);

	if (success)
	{
		*value = seed;
	}
	else
	{
		free(seed.ptr);
	}
	return success;
}

METHOD(diffie_hellman_t, get_shared_secret, bool,
	private_newhope_ke_t *this, chunk_t *secret)
{
	return FALSE;
}

METHOD(diffie_hellman_t, set_other_public_value, bool,
	private_newhope_ke_t *this, chunk_t value)
{
	return FALSE;
}

METHOD(diffie_hellman_t, get_dh_group, diffie_hellman_group_t,
	private_newhope_ke_t *this)
{
	return NH_128_BIT;
}

METHOD(diffie_hellman_t, destroy, void,
	private_newhope_ke_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
newhope_ke_t *newhope_ke_create(diffie_hellman_group_t group, chunk_t g, chunk_t p)
{
	private_newhope_ke_t *this;

	INIT(this,
		.public = {
			.dh = {
				.get_shared_secret = _get_shared_secret,
				.set_other_public_value = _set_other_public_value,
				.get_my_public_value = _get_my_public_value,
				.get_dh_group = _get_dh_group,
				.destroy = _destroy,
			},
		},
	);

	return &this->public;
}
