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

/* APFS Objects */

/* Object identifiers constants */
#define APFS_OID_NX_SUPERBLOCK			1
#define APFS_OID_INVALID			0ULL
#define APFS_OID_RESERVED_COUNT			1024

/* Object type masks */
#define APFS_OBJECT_TYPE_MASK			0x0000ffff
#define APFS_OBJECT_TYPE_FLAGS_MASK		0xffff0000
#define APFS_OBJ_STORAGETYPE_MASK		0xc0000000
#define APFS_OBJECT_TYPE_FLAGS_DEFINED_MASK	0xf8000000

/* Object types */
#define APFS_OBJECT_TYPE_NX_SUPERBLOCK		0x00000001
#define APFS_OBJECT_TYPE_BTREE			0x00000002
#define APFS_OBJECT_TYPE_BTREE_NODE		0x00000003
#define APFS_OBJECT_TYPE_SPACEMAN		0x00000005
#define APFS_OBJECT_TYPE_SPACEMAN_CAB		0x00000006
#define APFS_OBJECT_TYPE_SPACEMAN_CIB		0x00000007
#define APFS_OBJECT_TYPE_SPACEMAN_BITMAP	0x00000008
#define APFS_OBJECT_TYPE_SPACEMAN_FREE_QUEUE	0x00000009
#define APFS_OBJECT_TYPE_EXTENT_LIST_TREE	0x0000000a
#define APFS_OBJECT_TYPE_OMAP			0x0000000b
#define APFS_OBJECT_TYPE_CHECKPOINT_MAP		0x0000000c
#define APFS_OBJECT_TYPE_FS			0x0000000d
#define APFS_OBJECT_TYPE_FSTREE			0x0000000e
#define APFS_OBJECT_TYPE_BLOCKREFTREE		0x0000000f
#define APFS_OBJECT_TYPE_SNAPMETATREE		0x00000010
#define APFS_OBJECT_TYPE_NX_REAPER		0x00000011
#define APFS_OBJECT_TYPE_NX_REAP_LIST		0x00000012
#define APFS_OBJECT_TYPE_OMAP_SNAPSHOT		0x00000013
#define APFS_OBJECT_TYPE_EFI_JUMPSTART		0x00000014
#define APFS_OBJECT_TYPE_FUSION_MIDDLE_TREE	0x00000015
#define APFS_OBJECT_TYPE_NX_FUSION_WBC		0x00000016
#define APFS_OBJECT_TYPE_NX_FUSION_WBC_LIST	0x00000017
#define APFS_OBJECT_TYPE_ER_STATE		0x00000018
#define APFS_OBJECT_TYPE_GBITMAP		0x00000019
#define APFS_OBJECT_TYPE_GBITMAP_TREE		0x0000001a
#define APFS_OBJECT_TYPE_GBITMAP_BLOCK		0x0000001b
#define APFS_OBJECT_TYPE_INVALID		0x00000000
#define APFS_OBJECT_TYPE_TEST			0x000000ff

/* Object type flags */
#define APFS_OBJ_VIRTUAL			0x00000000
#define APFS_OBJ_EPHEMERAL			0x80000000
#define APFS_OBJ_PHYSICAL			0x40000000
#define APFS_OBJ_NOHEADER			0x20000000
#define APFS_OBJ_ENCRYPTED			0x10000000
#define APFS_OBJ_NONPERSISTENT			0x08000000

/*
 * On-disk representation of an APFS object
 */
struct apfs_obj_phys {
/*00*/	__le64 o_cksum;		/* Fletcher checksum */
	__le64 o_oid;		/* Object-id */
/*10*/	__le64 o_xid;		/* Transaction ID */
	__le32 o_type;		/* Object type */
	__le32 o_subtype;	/* Object subtype */
} __packed;

/*
 * In-memory representation of an APFS object
 */
struct apfs_object {
	struct super_block *sb;
	u64 block_nr;
	u64 oid;		/* Often the same as the block number */

	/*
	 * Buffer head containing the one block of the object.  TODO: support
	 * objects with more than one block.
	 */
	struct buffer_head *bh;
};

#define APFS_MAX_CKSUM_SIZE 8

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
