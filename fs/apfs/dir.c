// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/dir.c
 *
 * Copyright (C) 2018 Ernesto A. Fernandez <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/slab.h>
#include "apfs.h"

/**
 * apfs_inode_by_name - Find the cnid for a given filename
 * @dir:	parent directory
 * @child:	filename
 *
 * Returns the inode number (which is the cnid of the file record), or 0 in
 * case of failure.
 */
u64 apfs_inode_by_name(struct inode *dir, const struct qstr *child)
{
	int length;
	u64 cnid = dir->i_ino;
	struct apfs_cat_key *key;

	length = child->len + 1; /* Count the terminating null byte */
	key = kmalloc(sizeof(*key) + length, GFP_KERNEL);
	if (!key)
		return 0;
	/* We are looking for a key record */
	key->k_cnid = cpu_to_le64(cnid | ((u64)APFS_RT_KEY << 56));
	key->k_len = length;
	/*
	 * The 3 bytes of unknown meaning don't seem to matter for
	 * the search, so we don't set them.
	 */
	strcpy(key->k_filename, child->name);

	return apfs_cat_resolve(dir->i_sb, key);
}
