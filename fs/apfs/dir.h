/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/dir.h
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_DIR_H
#define _APFS_DIR_H

#include <linux/fs.h>
#include <linux/types.h>

/*
 * Structure of an on-disk dentry. This is the data in the catalog tables
 * for record type APFS_RT_DENTRY.
 *
 * Sometimes an extra 64-bit field will exist; this has something to do with
 * hard links. Either way, the cnid remains first.
 */
struct apfs_dentry {
	__le64 d_cnid;
	__le64 d_time;		/* Date Added */
	__le16 d_type;		/* File type */
} __attribute__ ((__packed__));

extern u64 apfs_inode_by_name(struct inode *dir, const struct qstr *child);

extern const struct file_operations apfs_dir_operations;

#endif	/* _APFS_DIR_H */
