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

/*
 * Structure used to store a range of physical blocks
 */
struct apfs_prange {
	__le64 pr_start_paddr;
	__le64 pr_block_count;
} __packed;

/* Main container */

/* Container constants */
#define APFS_NX_MAGIC				APFS_SUPER_MAGIC
#define APFS_NX_BLOCK_NUM			0
#define APFS_NX_MAX_FILE_SYSTEMS		100

#define APFS_NX_EPH_INFO_COUNT			4
#define APFS_NX_EPH_MIN_BLOCK_COUNT		8
#define APFS_NX_MAX_FILE_SYSTEM_EPH_STRUCTS	4
#define APFS_NX_TX_MIN_CHECKPOINT_COUNT		4
#define APFS_NX_EPH_INFO_VERSION_1		1

/* Container flags */
#define APFS_NX_RESERVED_1			0x00000001LL
#define APFS_NX_RESERVED_2			0x00000002LL
#define APFS_NX_CRYPTO_SW			0x00000004LL

/* Optional container feature flags */
#define APFS_NX_FEATURE_DEFRAG			0x0000000000000001ULL
#define APFS_NX_FEATURE_LCFD			0x0000000000000002ULL
#define APFS_NX_SUPPORTED_FEATURES_MASK		(APFS_NX_FEATURE_DEFRAG | \
						APFS_NX_FEATURE_LCFD)

/* Read-only compatible container feature flags */
#define APFS_NX_SUPPORTED_ROCOMPAT_MASK		(0x0ULL)

/* Incompatible container feature flags */
#define APFS_NX_INCOMPAT_VERSION1		0x0000000000000001ULL
#define APFS_NX_INCOMPAT_VERSION2		0x0000000000000002ULL
#define APFS_NX_INCOMPAT_FUSION			0x0000000000000100ULL
#define APFS_NX_SUPPORTED_INCOMPAT_MASK		(APFS_NX_INCOMPAT_VERSION2 \
						| APFS_NX_INCOMPAT_FUSION)

/* Block and container sizes */
#define APFS_NX_MINIMUM_BLOCK_SIZE		4096
#define APFS_NX_DEFAULT_BLOCK_SIZE		4096
#define APFS_NX_MAXIMUM_BLOCK_SIZE		65536
#define APFS_NX_MINIMUM_CONTAINER_SIZE		1048576

/* Indexes into a container superblock's array of counters */
enum {
	APFS_NX_CNTR_OBJ_CKSUM_SET	= 0,
	APFS_NX_CNTR_OBJ_CKSUM_FAIL	= 1,

	APFS_NX_NUM_COUNTERS		= 32
};

/*
 * On-disk representation of the container superblock
 */
struct apfs_nx_superblock {
/*00*/	struct apfs_obj_phys nx_o;
/*20*/	__le32 nx_magic;
	__le32 nx_block_size;
	__le64 nx_block_count;

/*30*/	__le64 nx_features;
	__le64 nx_readonly_compatible_features;
	__le64 nx_incompatible_features;

/*48*/	char nx_uuid[16];

/*58*/	__le64 nx_next_oid;
	__le64 nx_next_xid;

/*68*/	__le32 nx_xp_desc_blocks;
	__le32 nx_xp_data_blocks;
/*70*/	__le64 nx_xp_desc_base;
	__le64 nx_xp_data_base;
	__le32 nx_xp_desc_next;
	__le32 nx_xp_data_next;
/*88*/	__le32 nx_xp_desc_index;
	__le32 nx_xp_desc_len;
	__le32 nx_xp_data_index;
	__le32 nx_xp_data_len;

/*98*/	__le64 nx_spaceman_oid;
	__le64 nx_omap_oid;
	__le64 nx_reaper_oid;

/*B0*/	__le32 nx_test_type;

	__le32 nx_max_file_systems;
/*B8*/	__le64 nx_fs_oid[APFS_NX_MAX_FILE_SYSTEMS];
/*3D8*/	__le64 nx_counters[APFS_NX_NUM_COUNTERS];
/*4D8*/	struct apfs_prange nx_blocked_out_prange;
	__le64 nx_evict_mapping_tree_oid;
/*4F0*/	__le64 nx_flags;
	__le64 nx_efi_jumpstart;
/*500*/	char nx_fusion_uuid[16];
	struct apfs_prange nx_keylocker;
/*520*/	__le64 nx_ephemeral_info[APFS_NX_EPH_INFO_COUNT];

/*540*/	__le64 nx_test_oid;

	__le64 nx_fusion_mt_oid;
/*550*/	__le64 nx_fusion_wbc_oid;
	struct apfs_prange nx_fusion_wbc;
} __packed;

/* Mount option flags */
#define APFS_UID_OVERRIDE	1
#define APFS_GID_OVERRIDE	2

/*
 * Superblock data in memory, both from the main superblock and the volume
 * checkpoint superblock.
 */
struct apfs_sb_info {
	struct apfs_nx_superblock *s_msb_raw;		/* On-disk main sb */
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
/*00*/	struct apfs_obj_phys v_header;

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
