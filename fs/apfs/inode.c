// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/inode.c
 *
 * Copyright (C) 2018 Ernesto A. Fernandez <ernesto.mnd.fernandez@gmail.com>
 */

#include "apfs.h"

/* This function is just a shell for now so I can focus on the lookup */
struct inode *apfs_iget(struct super_block *sb, u64 cnid)
{
	struct inode *inode;
	unsigned long ino = cnid;

	if ((u64)ino < cnid) {
		/* How do we deal with 64 bit inode numbers on a 32 bit arch? */
		apfs_msg(sb, KERN_WARNING, "inode number overflow");
		return ERR_PTR(-EOVERFLOW);
	}
	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	/* TODO: read the actual inode from disk here */

	/* We assume a directory because that is all we can handle for now */
	inode->i_mode = S_IFDIR;
	inode->i_op = &apfs_dir_inode_operations;

	unlock_new_inode(inode);
	return inode;
}
