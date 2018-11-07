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
 * Structure of the value of a directory entry. This is the data in
 * the catalog tables for record type APFS_TYPE_DIR_REC.
 */
struct apfs_drec_val {
	__le64 file_id;
	__le64 date_added;
	__le16 flags;
	u8 xfields[];
} __packed;

extern u64 apfs_inode_by_name(struct inode *dir, const struct qstr *child);

extern const struct file_operations apfs_dir_operations;

#endif	/* _APFS_DIR_H */
