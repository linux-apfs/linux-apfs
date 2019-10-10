/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/transaction.h
 *
 * Copyright (C) 2019 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_TRANSACTION_H
#define _APFS_TRANSACTION_H

#include <linux/buffer_head.h>
#include <linux/list.h>
#include "node.h"

/*
 * Structure that keeps track of a transaction.
 */
struct apfs_transaction {
	struct buffer_head *t_old_msb;  /* Main superblock being replaced */
	struct buffer_head *t_old_vsb;  /* Volume superblock being replaced */

	struct apfs_node t_old_omap_root; /* Omap root node being replaced */
	struct apfs_node t_old_cat_root;  /* Catalog root node being replaced */

	struct list_head t_buffers;	/* List of buffers in the transaction */
};

/* State bits for buffer heads in a transaction */
#define BH_TRANS	BH_PrivateStart		/* Attached to a transaction */
#define BH_CSUM		(BH_PrivateStart + 1)	/* Requires checksum update */
BUFFER_FNS(TRANS, trans);
BUFFER_FNS(CSUM, csum);

/*
 * Additional information for a buffer in a transaction.
 */
struct apfs_bh_info {
	struct buffer_head	*bh;	/* The buffer head */
	struct list_head	list;	/* List of buffers in the transaction */
};

extern void apfs_cpoint_data_allocate(struct super_block *sb, u64 *bno);
extern int apfs_transaction_start(struct super_block *sb);
extern int apfs_transaction_commit(struct super_block *sb);
extern int apfs_transaction_join(struct super_block *sb,
				 struct buffer_head *bh);
void apfs_transaction_abort(struct super_block *sb);

#endif	/* _APFS_TRANSACTION_H */
