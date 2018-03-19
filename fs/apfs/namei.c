// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/namei.c
 *
 * Copyright (C) 2018 Ernesto A. Fernandez <ernesto.mnd.fernandez@gmail.com>
 */

#include "apfs.h"
#include "key.h"

static struct dentry *apfs_lookup(struct inode *dir, struct dentry *dentry,
				  unsigned int flags)
{
	struct inode *inode = NULL;
	u64 ino;

	if (dentry->d_name.len > APFS_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	ino = apfs_inode_by_name(dir, &dentry->d_name);
	if (ino) {
		inode = apfs_iget(dir->i_sb, ino);
		/* The module can't do much yet, so test by printing the cnid */
		apfs_msg(dir->i_sb, KERN_INFO, "inode found: %llu", ino);
	}
	return d_splice_alias(inode, dentry);
}

const struct inode_operations apfs_dir_inode_operations = {
	.lookup		= apfs_lookup,
	.listxattr      = apfs_listxattr,
};

const struct inode_operations apfs_special_inode_operations = {
	.listxattr      = apfs_listxattr,
};
