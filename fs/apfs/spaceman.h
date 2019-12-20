/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_SPACEMAN_H
#define _APFS_SPACEMAN_H

#include <linux/types.h>
#include "apfs_raw.h"

/*
 * Space manager data in memory.
 */
struct apfs_spaceman {
	struct apfs_spaceman_phys *sm_raw; /* On-disk spaceman structure */
	struct buffer_head	  *sm_bh;  /* Buffer head for @sm_raw */

	int sm_struct_size;		/* Actual size of @sm_raw */
	u32 sm_blocks_per_chunk;	/* Blocks covered by a bitmap block */
	u32 sm_chunks_per_cib;		/* Chunk count in a chunk-info block */
	u64 sm_block_count;		/* Block count for the container */
	u64 sm_chunk_count;		/* Number of bitmap blocks */
	u32 sm_cib_count;		/* Number of chunk-info blocks */
	u64 sm_free_count;		/* Number of free blocks */
	u32 sm_addr_offset;		/* Offset of cib addresses in @sm_raw */
};

extern int apfs_read_spaceman(struct super_block *sb);
extern int apfs_free_queue_insert(struct super_block *sb, u64 bno);
extern int apfs_spaceman_allocate_block(struct super_block *sb, u64 *bno);

#endif	/* _APFS_SPACEMAN_H */
