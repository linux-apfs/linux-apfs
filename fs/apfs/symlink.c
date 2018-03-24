// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/symlink.c
 *
 * Copyright (C) 2018 Ernesto A. Fernandez <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/slab.h>
#include "apfs.h"

/**
 * apfs_get_link - Follow a symbolic link
 * @dentry:	dentry for the link
 * @inode:	inode for the link
 * @done:	delayed call to free the returned buffer after use
 *
 * Returns a pointer to a buffer containing the target path, or an appropriate
 * error pointer in case of failure.
 */
static const char *apfs_get_link(struct dentry *dentry, struct inode *inode,
				 struct delayed_call *done)
{
	struct apfs_cat_symlink *link;
	char *err;
	int size;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	size = apfs_xattr_get(inode, "com.apple.fs.symlink",
			      NULL /* buffer */, 0 /* size */);
	if (size < 0) /* TODO: return a better error code */
		return ERR_PTR(size);
	if (size < sizeof(*link) + 1)
		return ERR_PTR(-EFSCORRUPTED);

	link = kmalloc(size, GFP_KERNEL);
	if (!link)
		return ERR_PTR(-ENOMEM);

	size = apfs_xattr_get(inode, "com.apple.fs.symlink", link, size);
	if (size < 0) {
		err = ERR_PTR(size);
		goto fail;
	}
	if (size != sizeof(*link) + le16_to_cpu(link->len) ||
	    *((char *)link + size - 1) != 0) {
		err = ERR_PTR(-EFSCORRUPTED);
		goto fail;
	}

	set_delayed_call(done, kfree_link, link);
	return link->target;

fail:
	kfree(link);
	return err;
}

const struct inode_operations apfs_symlink_inode_operations = {
	.get_link	= apfs_get_link,
	.listxattr	= apfs_listxattr,
};
