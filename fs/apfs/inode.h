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
	u64 i_crtime;			/* Time of creation */

	struct inode vfs_inode;
};

static inline struct apfs_inode_info *APFS_I(struct inode *inode)
{
	return container_of(inode, struct apfs_inode_info, vfs_inode);
}

/*
 * Structure of the data in the catalog tables for record type APFS_RT_INODE.
 * For some type of records there will be more data in an apfs_inode_tail
 * structure, right after the filename and some null bytes. As far as I know
 * this happens only for regular files, though some of them don't have it
 * either.
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
	__le64 unknown_4;
	__le16 i_datatype;
	__le16 i_len;		/* Filename length, counting null termination */

	/*
	 * Filename starts here, sometimes preceded by four bytes of unknown
	 * meaning. Also seems to be followed by a padding of null bytes.
	 * Don't try to work with this field for now.
	 */
	char i_filename[0];
} __attribute__ ((__packed__));

/*
 * Tail of the data for an APFS_RT_INODE record. I'm not sure where it starts,
 * since the padding of the filename is confusing, but it ends with the record.
 * For now we decide if this tail is present by checking if it fits.
 */
struct apfs_inode_tail {
	__le64 i_size;		/* Logical file size */
	__le64 i_phys_size;	/* Physical file size */
	char unknown[24];	/* Or is it 8 bytes? */
} __attribute__ ((__packed__));

extern struct inode *apfs_iget(struct super_block *sb, u64 cnid);

#endif	/* _APFS_INODE_H */
