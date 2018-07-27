/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/apfs.h
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_H
#define _APFS_H

#include <linux/fs.h>
#include <linux/types.h>

#define EFSCORRUPTED	EUCLEAN		/* Filesystem is corrupted */

#define APFS_DEFAULT_BLOCKSIZE	4096

/*
 * In-memory representation of an APFS node
 */
struct apfs_node {
	struct super_block *sb;
	u64 block_nr;
	u64 node_id;		/* Often the same as the block number */

	/*
	 * Buffer head containing the first block of the node. If the true
	 * blocksize of the file system is above PAGE_SIZE, then sb->blocksize
	 * should be set to PAGE_SIZE and more than one buffer head will be
	 * needed for each node. This is not yet implemented.
	 */
	struct buffer_head *bh;
};

/*
 * This structure apparently heads every metadata block
 */
struct apfs_node_header {
/*00*/	__le64 n_checksum;	/* Fletcher checksusum */
	__le64 n_block_id;	/* Either the object-id or the block number */
/*10*/	__le64 n_checkpoint_id;
	__le16 unknown_1;	/* Possible level in the b-tree */
	__le16 unknown_2;	/* Seems always 0x4000. Perhaps a flag */
	__le16 unknown_3;	/* Often 0x0b, 0x0e and 0x0f */
	__le16 unknown_4;
} __attribute__ ((__packed__));

/*
 * Structure of the data in the catalog tables for record type APFS_RT_EXTENT.
 */
struct apfs_cat_extent {
	__le64	length;		/* Length of the extent, in bytes */
	__le64	block;		/* Number of the first block in the extent */
	char	unknown[8];	/* Often all zeros */
} __attribute__ ((__packed__));

/*
 * Inode and file operations
 */

/* file.c */
extern const struct file_operations apfs_file_operations;
extern const struct inode_operations apfs_file_inode_operations;

/* namei.c */
extern const struct inode_operations apfs_dir_inode_operations;
extern const struct inode_operations apfs_special_inode_operations;
extern const struct dentry_operations apfs_dentry_operations;

/* symlink.c */
extern const struct inode_operations apfs_symlink_inode_operations;

#endif	/* _APFS_H */
