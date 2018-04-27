/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/super.h
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_SUPER_H
#define _APFS_SUPER_H

#include <linux/fs.h>
#include <linux/types.h>
#include "apfs.h"

#define APFS_SB_BLOCK	0

/* Mount option flags */
#define APFS_UID_OVERRIDE	1
#define APFS_GID_OVERRIDE	2

/*
 * Superblock data in memory, both from the main superblock and the volume
 * checkpoint superblock.
 */
struct apfs_sb_info {
	struct apfs_super_block *s_msb_raw;		/* On-disk main sb */
	struct apfs_volume_checkpoint_sb *s_vcsb_raw;	/* On-disk volume sb */

	struct apfs_table *s_cat_root;	/* Root of the catalog tree */
	struct apfs_table *s_btom_root;	/* Root of the b-tree object map */

	struct apfs_node s_mnode;	/* Node of the main superblock */
	struct apfs_node s_vnode;	/* Node of the volume checkpoint sb */

	/* Mount options */
	unsigned int s_flags;
	unsigned int s_vol_nr;		/* Index of the volume in the sb list */
	kuid_t s_uid;			/* uid to override on-disk uid */
	kgid_t s_gid;			/* gid to override on-disk gid */

	/* We must handle node sizes above the maximum blocksize of PAGE_SIZE */
	unsigned long s_nodesize;
	unsigned char s_nodesize_bits;
};

static inline struct apfs_sb_info *APFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

/*
 * Structure of the checkpoint and main superblocks
 */
struct apfs_super_block {
/*00*/	struct apfs_node_header	s_header;

/*20*/	__le32	s_magic;		/* NXSB */
	__le32	s_blksize;
/*28*/	__le64	s_blks_count;		/* Number of blocks in the container */
	char	unknown_2[24];
/*48*/	char	s_uuid[16];		/* uuid of the container */
	char	unknown_3[8];
/*60*/	__le64	s_next_checkpoint_id;
	char	unknown_4[8];

	/*
	 * The checkpoint superblock descriptor for the previous state is
	 * found in block s_base_blk + s_prev_csbd. The descriptor for
	 * this state is in block s_base_blk + s_curr_csbd. The oldest
	 * descriptor is in s_base_blk + s_oldest_csbd.
	 */
/*70*/	__le32	s_base_blk;
	char	unknown_5[12];
/*80*/	__le32	s_prev_csbd;		/* Or is it the next csbd? */
	char	unknown_6[4];
	__le32	s_curr_csbd;
	__le32	s_oldest_csbd;

	char	unknown_7[16];
/*A0*/	__le32	s_volume_index;		/* Volume Root Block */
	char	unknown_8[16];
	__le32	s_max_volumes;		/* Maximum number of volumes */
/*B8*/	__le64	volume_ids[0];		/* Array of volume ids starts here */
} __attribute__ ((__packed__));

/* Case sensitivity of the volume */
#define APFS_CASE_SENSITIVE		010
#define APFS_CASE_INSENSITIVE		001

/* The last volume has no size set and can use the rest of the blocks */
#define APFS_SIZE_UNLIMITED		0x0000

#define APFS_VOL_MAGIC	0x42535041

/*
 * Structure of each volume checkpoint superblock
 */
struct apfs_volume_checkpoint_sb {
/*00*/	struct apfs_node_header v_header;

/*20*/	__le32	v_magic;	/* APSB */
	__le32	v_number;	/* Volume number */
	char	unknown_1[16];
/*38*/	__le32	v_case_sens;	/* Case sensitivity of the volume */
	char	unknown_2[12];
/*48*/	__le64	v_blks_count;	/* Volume size in blocks */
	char	unknown_3[8];
/*58*/	__le64	v_used_blks;	/* Number of volume blocks in use */
	char	unknown_4[32];
/*80*/	__le64	v_btom;		/* First blk of b-tree object map for catalog */
	__le64	v_root;		/* Node ID of root node */
/*90*/	__le64	v_ext_btree;	/* Block number of extents b-tree */
	__le64	v_snapshots;	/* Block number to list of snapshots */
	char	unknown_5[16];
/*B0*/	__le64	v_next_cnid;
	__le64	v_file_count;	/* Number of files in the volume */
/*C0*/	__le64	v_dir_count;	/* Number of directories in the volume */
	char	unknown_6[40];
/*F0*/	char	v_uuid[16];	/* uuid of the volume */
/*100*/	__le64	v_wtime;	/* Last modification to the volume */
	char	unknown_7[8];
/*110*/	char	v_version[32];	/* Creator and APFS version */
/*130*/	__le64	v_crtime;	/* Volume creation time */
	char	unknown_8[8];

	/* List of volume checkpoints, each of them 0x30 bytes long */
/*140*/	struct {
		char	vc_creator[32];	/* Creator */
		__le64	vc_crtime;	/* Checkpoint creation time */
		__le64	vc_id;
	} v_checkpoints[8];

/*2C0*/	char	v_name[48];	/* Volume name */
} __attribute__ ((__packed__));

#endif	/* _APFS_SUPER_H */
