/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_EXTENTS_H
#define _APFS_EXTENTS_H

#include <linux/types.h>
#include "apfs_raw.h"

struct inode;
struct buffer_head;
struct apfs_query;

/*
 * Extent record data in memory
 */
struct apfs_file_extent {
	u64 logical_addr;
	u64 phys_block_num;
	u64 len;
};

extern int apfs_extent_from_query(struct apfs_query *query,
				  struct apfs_file_extent *extent);
extern int apfs_get_block(struct inode *inode, sector_t iblock,
			  struct buffer_head *bh_result, int create);

#endif	/* _APFS_EXTENTS_H */
