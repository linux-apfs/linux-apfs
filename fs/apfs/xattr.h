/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/xattr.h
 *
 * Copyright (C) 2018 Ernesto A. Fernandez <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _XATTR_H
#define _XATTR_H

#include <linux/types.h>

/*
 * Structure of the catalog data for xattrs of name "com.apple.fs.symlink",
 * which are used to implement symlinks.
 */
struct apfs_cat_symlink {
	char	unknown[2];
	__le16	len;		/* Length of target path (counting NULL) */
	char	target[0];	/* Target path (NULL-terminated) */
} __attribute__ ((__packed__));

extern int apfs_xattr_get(struct inode *inode, const char *name, void *buffer,
			  size_t size);
extern ssize_t apfs_listxattr(struct dentry *dentry, char *buffer, size_t size);

extern const struct xattr_handler *apfs_xattr_handlers[];

#endif	/* _XATTR_H */
