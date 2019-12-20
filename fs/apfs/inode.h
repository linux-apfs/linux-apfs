/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_INODE_H
#define _APFS_INODE_H

#include <linux/fs.h>
#include <linux/types.h>
#include "apfs_raw.h"
#include "extents.h"

/*
 * APFS inode data in memory
 */
struct apfs_inode_info {
	u64			i_ino64;	 /* 32-bit-safe inode number */
	u64			i_parent_id;	 /* ID of primary parent */
	u64			i_extent_id;	 /* ID of the extent records */
	struct apfs_file_extent	i_cached_extent; /* Latest extent record */
	spinlock_t		i_extent_lock;	 /* Protects i_cached_extent */
	struct timespec64	i_crtime;	 /* Time of creation */
	u32			i_nchildren;	 /* Child count for directory */
	uid_t			i_saved_uid;	 /* User ID on disk */
	gid_t			i_saved_gid;	 /* Group ID on disk */

	struct inode vfs_inode;
};

static inline struct apfs_inode_info *APFS_I(const struct inode *inode)
{
	return container_of(inode, struct apfs_inode_info, vfs_inode);
}

/**
 * apfs_ino - Get the 64-bit id of an inode
 * @inode: the vfs inode
 *
 * Returns all 64 bits of @inode's id, even on 32-bit architectures.
 */
static inline u64 apfs_ino(const struct inode *inode)
{
	return APFS_I(inode)->i_ino64;
}

/**
 * apfs_set_ino - Set a 64-bit id on an inode
 * @inode: the vfs inode
 * @id:	   id to set
 *
 * Sets both the vfs inode number and the actual 32-bit-safe id.
 */
static inline void apfs_set_ino(struct inode *inode, u64 id)
{
	inode->i_ino = id; /* Higher bits may be lost, but it doesn't matter */
	APFS_I(inode)->i_ino64 = id;
}

/* Make the compiler complain if we ever access i_ino directly by mistake */
#define i_ino	DONT_USE_I_INO

extern struct inode *apfs_iget(struct super_block *sb, u64 cnid);
extern int apfs_update_inode(struct inode *inode, char *new_name);
extern void apfs_evict_inode(struct inode *inode);
extern int apfs_getattr(const struct path *path, struct kstat *stat,
			u32 request_mask, unsigned int query_flags);
extern struct inode *apfs_new_inode(struct inode *dir, umode_t mode,
				    dev_t rdev);
extern int apfs_create_inode_rec(struct super_block *sb, struct inode *inode,
				 struct dentry *dentry);

#endif	/* _APFS_INODE_H */
