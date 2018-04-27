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
	int index_size = table->t_key - sizeof(struct apfs_table_raw);
	int entry_size;
	u16 type = table->t_type;

	if (table->t_key > sb->s_blocksize)
		return false;

	entry_size = (type & 0x04) ? sizeof(struct apfs_index_entry_short) :
		     sizeof(struct apfs_index_entry_long);

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
	struct apfs_table_raw *raw;
	struct apfs_table *table;

	bh = sb_bread(sb, block);
	if (!bh) {
		apfs_err(sb, "unable to read table");
		return NULL;
	}
	raw = (struct apfs_table_raw *) bh->b_data;

	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		goto release_bh;
	table->t_type = le16_to_cpu(raw->t_type);
	table->t_records = le16_to_cpu(raw->t_records);
	table->t_key = sizeof(*raw) + le16_to_cpu(raw->t_index_size);
	table->t_free = table->t_key + le16_to_cpu(raw->t_key_size);
	table->t_data = table->t_free + le16_to_cpu(raw->t_free_size);

	table->t_node.sb = sb;
	table->t_node.block_nr = block;
	table->t_node.node_id = le64_to_cpu(raw->t_header.n_block_id);
	table->t_node.bh = bh;

	if (!apfs_table_is_valid(sb, table)) {
		kfree(table);
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
	struct apfs_table_raw *raw;
	int type;
	int len;

	if (index >= table->t_records)
		return 0;

	raw = (struct apfs_table_raw *)table->t_node.bh->b_data;
	type = table->t_type;
	if (type & 0x04) {
		/* These table types have fixed length keys and data */
		struct apfs_index_entry_short *entry;

		entry = (struct apfs_index_entry_short *)raw->t_body + index;
		len = 16;
		/* Translate offset in key area to offset in block */
		*off = table->t_key + le16_to_cpu(entry->key_off);
	} else {
		/* These table types have variable length keys and data */
		struct apfs_index_entry_long *entry;

		entry = (struct apfs_index_entry_long *)raw->t_body + index;
		len = le16_to_cpu(entry->key_len);
		/* Translate offset in key area to offset in block */
		*off = table->t_key + le16_to_cpu(entry->key_off);
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
	struct apfs_table_raw *raw;
	int type;
	int len;

	if (index >= table->t_records)
		return 0;

	raw = (struct apfs_table_raw *)table->t_node.bh->b_data;
	type = table->t_type;
	if (type & 0x04) {
		/* These table types have fixed length keys and data */
		struct apfs_index_entry_short *entry;

		entry = (struct apfs_index_entry_short *)raw->t_body + index;
		len = (type & 0x02) ? 16 : 8; /* Table type decides length */
		/*
		 * Data offsets are counted backwards from the end of the
		 * block, or from the beginning of the footer when it exists
		 */
		if (type & 0x01) /* has footer */
			*off = sb->s_blocksize - 0x28 -
				le16_to_cpu(entry->data_off);
		else
			*off = sb->s_blocksize - le16_to_cpu(entry->data_off);
	} else {
		/* These table types have variable length keys and data */
		struct apfs_index_entry_long *entry;

		entry = (struct apfs_index_entry_long *)raw->t_body + index;
		len = le16_to_cpu(entry->data_len);
		/*
		 * Data offsets are counted backwards from the end of the
		 * block, or from the beginning of the footer when it exists
		 */
		if (type & 0x01) /* has footer */
			*off = sb->s_blocksize - 0x28 -
				le16_to_cpu(entry->data_off);
		else
			*off = sb->s_blocksize - le16_to_cpu(entry->data_off);
	}

	if (*off < 0 || *off + len > sb->s_blocksize) {
		/* Avoid out-of-bounds read if corrupted */
		return 0;
	}
	return len;
}

/**
 * apfs_table_query - Execute a query on a single table
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
int apfs_table_query(struct apfs_query *query)
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
		case APFS_QUERY_BTOM:
			err = apfs_read_btom_key(this_key, len, query->curr);
			break;
		case APFS_QUERY_VOL:
			err = apfs_read_vol_key(this_key, len, query->curr);
			break;
		default:
			/* Not implemented yet */
			err = -EINVAL;
			break;
		}
		if (err)
			return err;

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
