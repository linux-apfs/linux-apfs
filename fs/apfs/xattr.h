/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_XATTR_H
#define _APFS_XATTR_H

#include <linux/types.h>
#include "apfs_raw.h"
#include "inode.h"

/*
 * Xattr record data in memory
 */
struct apfs_xattr {
	u8 *name;
	u8 *xdata;
	int name_len;
	int xdata_len;
	bool has_dstream;
};

extern int __apfs_xattr_get(struct inode *inode, const char *name, void *buffer,
			    size_t size);
extern int apfs_xattr_get(struct inode *inode, const char *name, void *buffer,
			  size_t size);
extern ssize_t apfs_listxattr(struct dentry *dentry, char *buffer, size_t size);

extern const struct xattr_handler *apfs_xattr_handlers[];

#endif	/* _APFS_XATTR_H */
