/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_DIR_H
#define _APFS_DIR_H

#include <linux/types.h>
#include "apfs_raw.h"

struct inode;
struct dentry;
struct qstr;
struct apfs_query;

/*
 * Directory entry record in memory
 */
struct apfs_drec {
	u8 *name;
	u64 ino;
	u64 sibling_id; /* The sibling id; 0 if none */
	int name_len;
	unsigned int type;
};

extern int apfs_inode_by_name(struct inode *dir, const struct qstr *child,
			      u64 *ino);
extern int apfs_mknod(struct inode *dir, struct dentry *dentry,
		      umode_t mode, dev_t rdev);
extern int apfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode);
extern int apfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		       bool excl);
extern int apfs_link(struct dentry *old_dentry, struct inode *dir,
		     struct dentry *dentry);
extern int apfs_unlink(struct inode *dir, struct dentry *dentry);
extern int apfs_rmdir(struct inode *dir, struct dentry *dentry);
extern int apfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		       struct inode *new_dir, struct dentry *new_dentry,
		       unsigned int flags);
extern int apfs_delete_orphan_link(struct inode *inode);

extern const struct file_operations apfs_dir_operations;

#endif	/* _APFS_DIR_H */
