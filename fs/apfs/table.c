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

	if (table->t_key > sb->s_blocksize)
		return false;

	entry_size = (apfs_table_has_fixed_kv_size(table)) ?
		sizeof(struct apfs_kvoff) : sizeof(struct apfs_kvloc);

	return records * entry_size <= index_size;
}

static void apfs_table_release(struct kref *kref)
{
	struct apfs_table *table =
		container_of(kref, struct apfs_table, refcount);

	brelse(table->t_node.bh);
	kfree(table);
}

void apfs_table_get(struct apfs_table *table)
{
	kref_get(&table->refcount);
}

void apfs_table_put(struct apfs_table *table)
{
	kref_put(&table->refcount, apfs_table_release);
}

/**
 * apfs_read_table - Read a table header from disk
 * @sb:		filesystem superblock
 * @block:	number of the block where the table is stored
 *
 * Returns ERR_PTR in case of failure, otherwise return a pointer to the
 * resulting apfs_table structure with the initial reference taken.
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
		return ERR_PTR(-EINVAL);
	}
	raw = (struct apfs_btree_node_phys *) bh->b_data;

	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table) {
		brelse(bh);
		return ERR_PTR(-ENOMEM);
	}

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

	kref_init(&table->refcount);

	if (!apfs_table_is_valid(sb, table)) {
		apfs_alert(sb, "bad table in block 0x%llx", block);
		apfs_table_put(table);
		return ERR_PTR(-EFSCORRUPTED);
	}

	return table;
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
	if (apfs_table_has_fixed_kv_size(table)) {
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
	if (apfs_table_has_fixed_kv_size(table)) {
		/* These table types have fixed length keys and data */
		struct apfs_kvoff *entry;

		entry = (struct apfs_kvoff *)raw->btn_data + index;
		/* Node type decides length */
		len = apfs_table_is_leaf(table) ? 16 : 8;
		/*
		 * Data offsets are counted backwards from the end of the
		 * block, or from the beginning of the footer when it exists
		 */
		if (apfs_table_is_root(table)) /* has footer */
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
		if (apfs_table_is_root(table)) /* has footer */
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
 * apfs_key_from_query - Read the current key from a query structure
 * @query:	the query, with @query->key_off and @query->key_len already set
 * @key:	return parameter for the key, should be @query->curr
 *
 * Reads the key into @key and performs some basic sanity checks as a
 * protection against crafted filesystems.  Returns 0 on success or a
 * negative error code otherwise.
 */
static int apfs_key_from_query(struct apfs_query *query, struct apfs_key *key)
{
	struct super_block *sb = query->table->t_node.sb;
	char *raw = query->table->t_node.bh->b_data;
	void *raw_key = (void *)(raw + query->key_off);
	int err = 0;

	switch (query->flags & APFS_QUERY_TREE_MASK) {
	case APFS_QUERY_CAT:
		err = apfs_read_cat_key(raw_key, query->key_len, key);
		break;
	case APFS_QUERY_OMAP:
		err = apfs_read_omap_key(raw_key, query->key_len, query->curr);
		break;
	default:
		/* Not implemented yet */
		err = -EINVAL;
		break;
	}
	if (err) {
		apfs_alert(sb, "bad table key in block 0x%llx",
			   query->table->t_node.block_nr);
	}
	return err;
}

/**
 * apfs_table_next - Find the next matching record in the current table
 * @sb:		filesystem superblock
 * @query:	multiple query in execution
 *
 * Returns 0 on success, -EAGAIN if the next record is in another table,
 * -ENODATA if no more matching records exist, or another negative error
 * code in case of failure.
 */
static int apfs_table_next(struct super_block *sb, struct apfs_query *query)
{
	struct apfs_table *table = query->table;
	int cmp, err;

	if (query->flags & APFS_QUERY_DONE)
		/* Nothing left to search; the query failed */
		return -ENODATA;

	if (!query->index) /* The next record may be in another table */
		return -EAGAIN;
	--query->index;

	query->key_len = apfs_table_locate_key(table, query->index,
					       &query->key_off);
	err = apfs_key_from_query(query, query->curr);
	if (err)
		return err;

	cmp = apfs_keycmp(sb, query->curr, query->key);

	if (cmp > 0) /* Records are out of order */
		return -EFSCORRUPTED;

	if (cmp != 0 && apfs_table_is_leaf(table) &&
	    query->flags & APFS_QUERY_EXACT)
		return -ENODATA;

	query->len = apfs_table_locate_data(table, query->index, &query->off);
	if (query->len == 0)
		return -EFSCORRUPTED;

	if (cmp != 0) {
		/*
		 * This is the last entry that can be relevant in this table.
		 * Keep searching the children, but don't return to this level.
		 */
		query->flags |= APFS_QUERY_DONE;
	}

	return 0;
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

	if (query->flags & APFS_QUERY_NEXT)
		return apfs_table_next(sb, query);

	while (--query->index >= 0) {
		int cmp, err;

		query->key_len = apfs_table_locate_key(table, query->index,
						       &query->key_off);
		err = apfs_key_from_query(query, query->curr);
		if (err)
			return err;

		cmp = apfs_keycmp(sb, query->curr, query->key);

		if (cmp <= 0) {
			if (apfs_table_is_leaf(query->table) &&
			    query->flags & APFS_QUERY_EXACT &&
			    cmp != 0)
				return -ENODATA;

			query->len = apfs_table_locate_data(table, query->index,
							    &query->off);
			if (query->len == 0)
				return -EFSCORRUPTED;

			if (query->flags & APFS_QUERY_MULTIPLE) {
				if (cmp != 0) /* Last relevant entry in level */
					query->flags |= APFS_QUERY_DONE;
				query->flags |= APFS_QUERY_NEXT;
			}
			return 0;
		}
	}

	return -ENODATA;
}

/**
 * apfs_bno_from_query - Read the block number found by a successful omap query
 * @query:	the query that found the record
 * @bno:	Return parameter.  The block number found.
 *
 * Reads the block number in the omap record into @bno and performs a basic
 * sanity check as a protection against crafted filesystems.  Returns 0 on
 * success or -EFSCORRUPTED otherwise.
 */
int apfs_bno_from_query(struct apfs_query *query, u64 *bno)
{
	struct apfs_omap_val *omap_val;
	char *raw = query->table->t_node.bh->b_data;

	if (query->len != sizeof(*omap_val))
		return -EFSCORRUPTED;

	omap_val = (struct apfs_omap_val *)(raw + query->off);
	*bno = le64_to_cpu(omap_val->ov_paddr);
	return 0;
}
