/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/xattr.h
 *
 * Copyright (C) 2018 Ernesto A. Fernandez <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_XATTR_H
#define _APFS_XATTR_H

#include <linux/types.h>

/* xattr header flags */
#define APFS_XATTR_HAS_EXTENTS	0x0001	/* The xattr value is kept on extents */

/*
 * This structure heads the data of all xattr catalog entries
 */
struct apfs_xattr_header {
	__le16	flags;
	__le16	len;		/* Length of the xattr body */
} __attribute__ ((__packed__));

/*
 * Structure of xattr catalog entries with an inline value
 */
struct apfs_xattr_inline {
	struct apfs_xattr_header header;

	char value[0];	/* Value of the xattr */
} __attribute__ ((__packed__));

/*
 * Structure of xattr catalog entries that keep their value on extents
 */
struct apfs_xattr_ext {
	struct apfs_xattr_header header;

	__le64	cnid;		/* Catalog id for the value extents */
	__le64	size;		/* Logical size of the value */
	__le64	phys_size;	/* Physical size of the value */
	char	unknown[24];
} __attribute__ ((__packed__));

extern int apfs_xattr_get(struct inode *inode, const char *name, void *buffer,
			  size_t size);
extern ssize_t apfs_listxattr(struct dentry *dentry, char *buffer, size_t size);

extern const struct xattr_handler *apfs_xattr_handlers[];

#endif	/* _APFS_XATTR_H */
