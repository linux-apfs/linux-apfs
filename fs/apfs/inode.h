/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/inode.h
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_INODE_H
#define _APFS_INODE_H

#include <linux/fs.h>
#include <linux/types.h>

/*
 * APFS inode data in memory
 */
struct apfs_inode_info {
	struct timespec i_crtime;	/* Time of creation */

	struct inode vfs_inode;
};

static inline struct apfs_inode_info *APFS_I(struct inode *inode)
{
	return container_of(inode, struct apfs_inode_info, vfs_inode);
}

/* Optional attribute types observed so far */
#define APFS_INODE_NAME	0x0204
#define APFS_INODE_SIZE	0x2008
#define APFS_INODE_UNK1	0x280D
#define APFS_INODE_UNK2	0x0005

/*
 * Structure of an on-disk inode. This is the data in the catalog tables
 * for record type APFS_RT_INODE.
 */
struct apfs_inode {
	__le64 i_parent;	/* Parent ID */
	__le64 i_node;		/* Node ID */
	__le64 i_crtime;	/* File creation time */
	__le64 i_mtime;		/* Last write time */
	__le64 i_ctime;		/* Last inode change time */
	__le64 i_atime;		/* Last access time */
	__le64 unknown_1;
	union {
		__le64 i_child_count;	/* Children inodes of a directory */
		__le64 i_link_count;	/* Hard links to a regular file */
		char unknown_5[8];	/* Something else for special files */
	};
	__le64 unknown_2;
	__le32 i_owner;		/* ID of the owner */
	__le32 i_group;		/* ID of the group */
	__le16 i_mode;
	char unknown_3[6];	/* Flags of some kind? */
	__le32 unknown_4;

	/*
	 * The inode is followed by a variable number of optional attributes.
	 * Their type and length are declared here.
	 */
	__le16 i_attr_count;	/* Number of the attributes */
	__le16 i_attr_len;	/* Length of the attributes */
	struct {
		__le16 ia_type;	/* Attr type */
		__le16 ia_len;	/* Attr length (not counting padding) */
	} i_opt_attrs[0];
} __attribute__ ((__packed__));

/*
 * Optional attribute of type APFS_INODE_SIZE, storing the size of the inode
 */
struct apfs_inode_size {
	__le64 i_size;		/* Logical file size */
	__le64 i_phys_size;	/* Physical file size */
	char unknown[24];	/* Or is it 8 bytes? */
} __attribute__ ((__packed__));

extern struct inode *apfs_iget(struct super_block *sb, u64 cnid);
extern int apfs_getattr(const struct path *path, struct kstat *stat,
			u32 request_mask, unsigned int query_flags);

#endif	/* _APFS_INODE_H */
