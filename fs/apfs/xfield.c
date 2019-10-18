// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/xfield.c
 *
 * Copyright (C) 2019 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/kernel.h>
#include "xfield.h"

/**
 * apfs_find_xfield - Find an extended field value in an inode or dentry record
 * @xfields:	pointer to the on-disk xfield collection for the record
 * @len:	length of the collection
 * @xtype:	type of the xfield to retrieve
 * @xval:	on return, a pointer to the wanted on-disk xfield value
 *
 * Returns the length of @xval on success, or 0 if no matching xfield was found;
 * the caller must check that the expected structures fit before casting @xval.
 */
int apfs_find_xfield(u8 *xfields, int len, u8 xtype, char **xval)
{
	struct apfs_xf_blob *blob;
	struct apfs_x_field *xfield;
	int count;
	int rest = len;
	int i;

	if (!len)
		return 0; /* No xfield data */

	rest -= sizeof(*blob);
	if (rest < 0)
		return 0; /* Corruption */
	blob = (struct apfs_xf_blob *)xfields;

	count = le16_to_cpu(blob->xf_num_exts);
	rest -= count * sizeof(*xfield);
	if (rest < 0)
		return 0; /* Corruption */
	xfield = (struct apfs_x_field *)blob->xf_data;

	for (i = 0; i < count; ++i) {
		int xlen;

		/* Attribute length is padded to a multiple of 8 */
		xlen = round_up(le16_to_cpu(xfield[i].x_size), 8);
		if (xlen > rest)
			return 0; /* Corruption */

		if (xfield[i].x_type == xtype) {
			*xval = (char *)xfields + len - rest;
			return xlen;
		}
		rest -= xlen;
	}
	return 0;
}
