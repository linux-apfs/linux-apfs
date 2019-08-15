/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/dir.h
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_DIR_H
#define _APFS_DIR_H

#include <linux/types.h>

struct inode;
struct dentry;
struct qstr;
struct apfs_query;

/*
 * Structure of the value for a sibling link record.  These are used to
 * list the hard links for a given inode.
 */
struct apfs_sibling_val {
	__le64 parent_id;
	__le16 name_len;
	u8 name[0];
} __packed;

/*
 * Structure of the value for a sibling map record.  No idea what these are for.
 */
struct apfs_sibling_map_val {
	__le64 file_id;
} __packed;

/*
 * Structure of the value of a directory entry. This is the data in
 * the catalog nodes for record type APFS_TYPE_DIR_REC.
 */
struct apfs_drec_val {
	__le64 file_id;
	__le64 date_added;
	__le16 flags;
	u8 xfields[];
} __packed;

/*
 * Directory entry record in memory
 */
struct apfs_drec {
	u8 *name;
	u64 ino;
	int name_len;
	unsigned int type;
};

extern int apfs_drec_from_query(struct apfs_query *query,
				struct apfs_drec *drec);
extern int apfs_inode_by_name(struct inode *dir, const struct qstr *child,
			      u64 *ino);
extern int apfs_mknod(struct inode *dir, struct dentry *dentry,
		      umode_t mode, dev_t rdev);
extern int apfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode);
extern int apfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		       bool excl);
extern int apfs_link(struct dentry *old_dentry, struct inode *dir,
		     struct dentry *dentry);

extern const struct file_operations apfs_dir_operations;

#endif	/* _APFS_DIR_H */
