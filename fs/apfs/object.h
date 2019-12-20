/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_OBJECT_H
#define _APFS_OBJECT_H

#include <linux/types.h>
#include "apfs_raw.h"

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

extern int apfs_obj_verify_csum(struct super_block *sb,
				struct apfs_obj_phys *obj);
extern void apfs_obj_set_csum(struct super_block *sb,
			      struct apfs_obj_phys *obj);
extern int apfs_create_cpoint_map(struct super_block *sb, u64 oid, u64 bno);
extern struct buffer_head *apfs_read_ephemeral_object(struct super_block *sb,
						      u64 oid);
extern struct buffer_head *apfs_read_object_block(struct super_block *sb,
						  u64 bno, bool write);

#endif	/* _APFS_OBJECT_H */
