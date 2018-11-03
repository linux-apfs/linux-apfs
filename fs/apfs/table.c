// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/table.c
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/slab.h>
#include <linux/buffer_head.h>
#include "apfs.h"
#include "btree.h"
#include "key.h"
#include "message.h"
#include "super.h"
#include "table.h"

/**
 * apfs_table_is_valid - Check basic sanity of the table index
 * @sb:		filesystem superblock
 * @table:	table to check
 *
 * Verifies that the table index fits in a single block, and that the number
 * of records fits in the index. Without this check a crafted filesystem could
 * pretend to have too many records, and calls to apfs_table_locate_key() and
 * apfs_table_locate_data() would read beyond the limits of the node.
 */
static bool apfs_table_is_valid(struct super_block *sb,
				struct apfs_table *table)
{
	int records = table->t_records;
	int index_size = table->t_key - sizeof(struct apfs_btree_node_phys);
	int entry_size;
	u16 flags = table->t_flags;

	if (table->t_key > sb->s_blocksize)
		return false;

	entry_size = (flags & APFS_BTNODE_FIXED_KV_SIZE) ?
		sizeof(struct apfs_kvoff) : sizeof(struct apfs_kvloc);

	return records * entry_size <= index_size;
}

/**
 * apfs_read_table - Read a table header from disk
 * @sb:		filesystem superblock
 * @block:	number of the block where the table is stored
 *
 * Returns NULL in case of failure, otherwise a pointer to the resulting
 * apfs_table structure.
 *
 * For now we assume the table has not been read before.
 */
struct apfs_table *apfs_read_table(struct super_block *sb, u64 block)
{
	struct buffer_head *bh;
	struct apfs_btree_node_phys *raw;
	struct apfs_table *table;

	bh = sb_bread(sb, block);
	if (!bh) {
		apfs_err(sb, "unable to read table");
		return NULL;
	}
	raw = (struct apfs_btree_node_phys *) bh->b_data;

	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		goto release_bh;
	table->t_flags = le16_to_cpu(raw->btn_flags);
	table->t_records = le16_to_cpu(raw->btn_nkeys);
	table->t_key = sizeof(*raw) + le16_to_cpu(raw->btn_table_space.off)
				+ le16_to_cpu(raw->btn_table_space.len);
	table->t_free = table->t_key + le16_to_cpu(raw->btn_free_space.off);
	table->t_data = table->t_free + le16_to_cpu(raw->btn_free_space.len);

	table->t_node.sb = sb;
	table->t_node.block_nr = block;
	table->t_node.node_id = le64_to_cpu(raw->btn_o.o_oid);
	table->t_node.bh = bh;

	if (!apfs_table_is_valid(sb, table)) {
		kfree(table);
		apfs_alert(sb, "bad table in block 0x%llx", block);
		table = NULL;
		goto release_bh;
	}
	return table;

release_bh:
	brelse(bh);
	return table;
}

/**
 * apfs_release_table - Release a table structure
 * @table: table to release. If NULL, do nothing.
 */
void apfs_release_table(struct apfs_table *table)
{
	if (!table)
		return;
	brelse(table->t_node.bh);
	kfree(table);
}

/**
 * apfs_table_locate_key - Locate the key of a table entry
 * @table:	table node to be searched
 * @index:	number of the entry to locate
 * @off:	on return will hold the offset in the block
 *
 * Returns the length of the key, or 0 in case of failure. The function checks
 * that this length fits within the block; callers must use the returned value
 * to make sure they never operate outside its bounds.
 */
int apfs_table_locate_key(struct apfs_table *table, int index, int *off)
{
	struct super_block *sb = table->t_node.sb;
	struct apfs_btree_node_phys *raw;
	int flags;
	int len;

	if (index >= table->t_records)
		return 0;

	raw = (struct apfs_btree_node_phys *)table->t_node.bh->b_data;
	flags = table->t_flags;
	if (flags & APFS_BTNODE_FIXED_KV_SIZE) {
		struct apfs_kvoff *entry;

		entry = (struct apfs_kvoff *)raw->btn_data + index;
		len = 16;
		/* Translate offset in key area to offset in block */
		*off = table->t_key + le16_to_cpu(entry->k);
	} else {
		/* These table types have variable length keys and data */
		struct apfs_kvloc *entry;

		entry = (struct apfs_kvloc *)raw->btn_data + index;
		len = le16_to_cpu(entry->k.len);
		/* Translate offset in key area to offset in block */
		*off = table->t_key + le16_to_cpu(entry->k.off);
	}

	if (*off + len > sb->s_blocksize) {
		/* Avoid out-of-bounds read if corrupted */
		return 0;
	}
	return len;
}

/**
 * apfs_table_locate_data - Locate the data of a table entry
 * @table:	table node to be searched
 * @index:	number of the entry to locate
 * @off:	on return will hold the offset in the block
 *
 * Returns the length of the data, or 0 in case of failure. The function checks
 * that this length fits within the block; callers must use the returned value
 * to make sure they never operate outside its bounds.
 */
int apfs_table_locate_data(struct apfs_table *table, int index, int *off)
{
	struct super_block *sb = table->t_node.sb;
	struct apfs_btree_node_phys *raw;
	int flags;
	int len;

	if (index >= table->t_records)
		return 0;

	raw = (struct apfs_btree_node_phys *)table->t_node.bh->b_data;
	flags = table->t_flags;
	if (flags & APFS_BTNODE_FIXED_KV_SIZE) {
		/* These table types have fixed length keys and data */
		struct apfs_kvoff *entry;

		entry = (struct apfs_kvoff *)raw->btn_data + index;
		/* Node type decides length */
		len = (flags & APFS_BTNODE_LEAF) ? 16 : 8;
		/*
		 * Data offsets are counted backwards from the end of the
		 * block, or from the beginning of the footer when it exists
		 */
		if (flags & APFS_BTNODE_ROOT) /* has footer */
			*off = sb->s_blocksize - sizeof(struct apfs_btree_info)
					- le16_to_cpu(entry->v);
		else
			*off = sb->s_blocksize - le16_to_cpu(entry->v);
	} else {
		/* These table types have variable length keys and data */
		struct apfs_kvloc *entry;

		entry = (struct apfs_kvloc *)raw->btn_data + index;
		len = le16_to_cpu(entry->v.len);
		/*
		 * Data offsets are counted backwards from the end of the
		 * block, or from the beginning of the footer when it exists
		 */
		if (flags & APFS_BTNODE_ROOT) /* has footer */
			*off = sb->s_blocksize - sizeof(struct apfs_btree_info)
					- le16_to_cpu(entry->v.off);
		else
			*off = sb->s_blocksize - le16_to_cpu(entry->v.off);
	}

	if (*off < 0 || *off + len > sb->s_blocksize) {
		/* Avoid out-of-bounds read if corrupted */
		return 0;
	}
	return len;
}

/**
 * apfs_table_query - Execute a query on a single table
 * @sb:		filesystem superblock
 * @query:	the query to execute
 *
 * The search will start at index @query->index, looking for the key that comes
 * right before @query->key, according to the order given by apfs_keycmp().
 *
 * The @query->index will be updated to the last index checked. This is
 * important when searching for multiple entries, since the query may need
 * to remember where it was on this level. If we are done with this table, the
 * query will be flagged as APFS_QUERY_DONE, and the search will end in failure
 * as soon as we return to this level. The function may also return -EAGAIN,
 * to signal that the search should go on in a different branch.
 *
 * On success returns 0; the offset of the data within the block will be saved
 * in @query->off, and its length in @query->len. The function checks that this
 * length fits within the block; callers must use the returned value to make
 * sure they never operate outside its bounds.
 *
 * -ENODATA will be returned if no appropriate entry was found, -EFSCORRUPTED
 * in case of corruption.
 *
 * TODO: the search algorithm is far from optimal for the ordered case, it
 * would be better to search by bisection.
 */
int apfs_table_query(struct super_block *sb, struct apfs_query *query)
{
	struct apfs_table *table = query->table;

	if (query->flags & APFS_QUERY_DONE)
		/* Nothing left to search; the query failed */
		return -ENODATA;

	while (--query->index >= 0) {
		char *raw = table->t_node.bh->b_data;
		void *this_key;
		int off, len;
		int cmp;
		int err;

		len = apfs_table_locate_key(table, query->index, &off);
		this_key = (void *)(raw + off);

		switch (query->flags & APFS_QUERY_TREE_MASK) {
		case APFS_QUERY_CAT:
			err = apfs_read_cat_key(this_key, len, query->curr);
			break;
		case APFS_QUERY_OMAP:
			err = apfs_read_omap_key(this_key, len, query->curr);
			break;
		case APFS_QUERY_VOL:
			err = apfs_read_vol_key(this_key, len, query->curr);
			break;
		default:
			/* Not implemented yet */
			err = -EINVAL;
			break;
		}
		if (err) {
			apfs_alert(sb, "bad table key in block 0x%llx",
				   table->t_node.block_nr);
			return err;
		}

		cmp = apfs_keycmp(query->curr, query->key);

		if (cmp <= 0) {
			if (apfs_table_is_leaf(query->table) &&
			    query->flags & APFS_QUERY_EXACT &&
			    cmp != 0)
				return -ENODATA;

			query->key_off = off;
			query->key_len = len;

			len = apfs_table_locate_data(table, query->index, &off);
			if (len == 0)
				return -EFSCORRUPTED;
			query->off = off;
			query->len = len;
			if (apfs_table_is_leaf(query->table) &&
			    query->flags & APFS_QUERY_MULTIPLE &&
			    cmp != 0) {
				/*
				 * This is the last entry that can be relevant
				 * in this table. Keep searching the children,
				 * but don't come back to this level.
				 */
				query->flags |= APFS_QUERY_DONE;
			}
			return 0;
		}
	}

	if (query->flags & APFS_QUERY_MULTIPLE) {
		/* The next record may be in another table */
		return -EAGAIN;
	}

	return -ENODATA;
}
