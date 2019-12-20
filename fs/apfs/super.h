/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_SUPER_H
#define _APFS_SUPER_H

#include <linux/fs.h>
#include <linux/types.h>
#include "apfs_raw.h"
#include "object.h"
#include "spaceman.h"
#include "transaction.h"

/* Mount option flags */
#define APFS_CHECK_NODES	1

/*
 * Superblock data in memory, both from the main superblock and the volume
 * checkpoint superblock.
 */
struct apfs_sb_info {
	struct apfs_nx_superblock *s_msb_raw;		/* On-disk main sb */
	struct apfs_superblock *s_vsb_raw;		/* On-disk volume sb */

	u64 s_xid;			/* Latest transaction id */
	struct apfs_node *s_cat_root;	/* Root of the catalog tree */
	struct apfs_node *s_omap_root;	/* Root of the object map tree */

	struct apfs_object s_mobject;	/* Main superblock object */
	struct apfs_object s_vobject;	/* Volume superblock object */

	/* Mount options */
	unsigned int s_flags;
	unsigned int s_vol_nr;		/* Index of the volume in the sb list */
	kuid_t s_uid;			/* uid to override on-disk uid */
	kgid_t s_gid;			/* gid to override on-disk gid */

	/* TODO: handle block sizes above the maximum of PAGE_SIZE? */
	unsigned long s_blocksize;
	unsigned char s_blocksize_bits;

	struct inode *s_private_dir;	/* Inode for the private directory */

	struct apfs_spaceman s_spaceman;
	struct apfs_transaction s_transaction;

	/* For now, a single semaphore for every operation */
	struct rw_semaphore s_big_sem;
};

static inline struct apfs_sb_info *APFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline bool apfs_is_case_insensitive(struct super_block *sb)
{
	return (APFS_SB(sb)->s_vsb_raw->apfs_incompatible_features &
	       cpu_to_le64(APFS_INCOMPAT_CASE_INSENSITIVE)) != 0;
}

/**
 * apfs_max_maps_per_block - Find the maximum map count for a mapping block
 * @sb: superblock structure
 */
static inline int apfs_max_maps_per_block(struct super_block *sb)
{
	unsigned long maps_size;

	maps_size = (sb->s_blocksize - sizeof(struct apfs_checkpoint_map_phys));
	return maps_size / sizeof(struct apfs_checkpoint_mapping);
}

extern int apfs_map_volume_super(struct super_block *sb, bool write);
extern int apfs_read_omap(struct super_block *sb, bool write);
extern int apfs_read_catalog(struct super_block *sb, bool write);

#endif	/* _APFS_SUPER_H */
