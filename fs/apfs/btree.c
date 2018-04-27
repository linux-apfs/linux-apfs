// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/btree.c
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/buffer_head.h>
#include "apfs.h"
#include "btree.h"
#include "dir.h"
#include "key.h"
#include "message.h"
#include "super.h"
#include "table.h"

/**
 * apfs_alloc_query - Allocates a query structure
 * @table:	table to be searched
 * @parent:	query for the parent table
 *
 * Callers other than apfs_btree_query() should set @parent to NULL, and @table
 * to the root of the b-tree. They should also initialize most of the query
 * fields themselves; when @parent is not NULL the query will inherit them.
 *
 * Returns the allocated query, or NULL in case of failure.
 */
struct apfs_query *apfs_alloc_query(struct apfs_table *table,
				    struct apfs_query *parent)
{
	struct apfs_query *query;
	struct apfs_key *curr;

	query = kmalloc(sizeof(*query), GFP_KERNEL);
	if (!query)
		goto fail;

	/*
	 * The curr field exists because it seems wasteful to allocate a
	 * new apfs_key struct every time we read a key from disk during
	 * the search. Not sure it actually makes a difference.
	 */
	curr = kmalloc(sizeof(*curr), GFP_KERNEL);
	if (!curr)
		goto fail;

	query->table = table;
	query->key = parent ? parent->key : NULL;
	query->curr = curr;
	query->flags = parent ? parent->flags & ~APFS_QUERY_DONE : 0;
	query->parent = parent;
	/* Start the search with the last record and go backwards */
	query->index = table->t_records;
	query->depth = parent ? parent->depth + 1 : 0;

	return query;

fail:
	kfree(query);
	return NULL;
}

/**
 * apfs_free_query - Free a query structure
 * @sb:		filesystem superblock
 * @query:	query to free
 *
 * Also frees the current key, the table if it's not root of a b-tree, and
 * the parent query if it is kept. If a search key was allocated, the caller
 * still needs to free it.
 */
void apfs_free_query(struct super_block *sb, struct apfs_query *query)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_table *root = sbi->s_cat_root;
	struct apfs_table *btom = sbi->s_btom_root;

	kfree(query->curr);
	if (query->table != root && query->table != btom)
		apfs_release_table(query->table);
	if (query->parent)
		apfs_free_query(sb, query->parent);
	kfree(query);
}

/**
 * apfs_btree_query - Execute a query on a b-tree
 * @sb:		filesystem superblock
 * @query:	the query to execute
 *
 * Searches the b-tree starting at @query->index in @query->table, looking for
 * the record corresponding to @query->key.
 *
 * Returns 0 in case of success and sets the @query->len, @query->off and
 * @query->index fields to the results of the query. @query->table will now
 * point to the leaf node holding the record.
 *
 * In case of failure returns an appropriate error code.
 */
int apfs_btree_query(struct super_block *sb, struct apfs_query **query)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_table *root = sbi->s_cat_root;
	struct apfs_table *btom = sbi->s_btom_root;
	struct apfs_table *table;
	struct apfs_query *btom_query;
	struct apfs_key *btom_key;
	struct apfs_query *parent;
	struct apfs_btom_data *data;
	char *raw = (*query)->table->t_node.bh->b_data;
	u64 child = 0;
	int err;

	if ((*query)->depth >= 12) {
		/*
		 * We need a maximum depth for the tree so we can't loop
		 * forever if the filesystem is damaged. 12 should be more
		 * than enough to map every block.
		 */
		return -EFSCORRUPTED;
	}

	err = apfs_table_query(*query);
	if (err == -EAGAIN) {
		if (!(*query)->parent) /* We are at the root of the tree */
			return -ENODATA;

		/* Move back up one level and continue the query */
		parent = (*query)->parent;
		(*query)->parent = NULL; /* Don't free the parent */
		apfs_free_query(sb, *query);
		*query = parent;
		/* TODO: a crafted fs could have us spinning for too long */
		return apfs_btree_query(sb, query);
	}
	if (err)
		return err;
	if (apfs_table_is_leaf((*query)->table)) /* All done */
		return 0;
	if ((*query)->flags & APFS_QUERY_BTOM) {
		/* The data on a btom index node is the address of the child */
		if ((*query)->len != 8)
			return -EFSCORRUPTED;
		child = le64_to_cpup((__le64 *)(raw + (*query)->off));
	} else {
		/*
		 * The data on an index node is the id of the table
		 * to search next; we must query the btom to find its
		 * block number.
		 */
		if ((*query)->len != 8)
			return -EFSCORRUPTED;
		child = le64_to_cpup((__le64 *)(raw + (*query)->off));

		btom_query = apfs_alloc_query(btom, NULL /* parent */);
		if (!btom_query)
			return -ENOMEM;

		btom_key = kmalloc(sizeof(*btom_key), GFP_KERNEL);
		if (!btom_key) {
			err = -ENOMEM;
			goto fail;
		}
		apfs_init_key(0 /* type */, child, NULL /* name */,
			      0 /* namelen */, 0 /* offset */, btom_key);
		btom_query->key = btom_key;
		btom_query->flags |= APFS_QUERY_BTOM | APFS_QUERY_EXACT;

		err = apfs_btree_query(sb, &btom_query);
		kfree(btom_key);
		if (err)
			goto fail;
		raw = btom_query->table->t_node.bh->b_data;
		if (btom_query->len != sizeof(*data)) {
			err = -EFSCORRUPTED;
			goto fail;
		}
		data = (struct apfs_btom_data *)(raw + btom_query->off);
		child = le64_to_cpu(data->block);

		apfs_free_query(sb, btom_query);
	}

	/* Now go a level deeper and search the child */
	table = apfs_read_table(sb, child);
	if (!table)
		return -ENOMEM;

	if ((*query)->flags & APFS_QUERY_MULTIPLE) {
		/*
		 * We are looking for multiple entries, so we must remember
		 * the parent table and index to continue the search later.
		 */
		*query = apfs_alloc_query(table, *query);
	} else {
		/* Reuse the same query structure to search the child */
		if ((*query)->table != root && (*query)->table != btom)
			apfs_release_table((*query)->table);
		(*query)->table = table;
		(*query)->index = table->t_records;
		(*query)->depth++;
	}

	return apfs_btree_query(sb, query);

fail:
	apfs_free_query(sb, btom_query);
	return err;
}

/**
 * apfs_cat_get_data - Get the data for a catalog key
 * @sb:		filesystem superblock
 * @key:	catalog key
 * @length:	on return it will hold the length of the data
 * @table:	on return it will point to the table that stores the data
 *
 * Returns a pointer to the data, which will consist of @len bytes; or NULL
 * in case of failure.
 *
 * The caller must release @table (unless it's NULL) after using the data. The
 * exception is the root table, that should never be released. This is messy;
 * I have to rework it.
 */
void *apfs_cat_get_data(struct super_block *sb, struct apfs_key *key,
			int *length, struct apfs_table **table)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_query *query;
	void *data = NULL;

	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query)
		return NULL;
	query->key = key;
	query->flags |= APFS_QUERY_CAT | APFS_QUERY_EXACT;

	if (apfs_btree_query(sb, &query))
		goto fail;

	*table = query->table;
	*length = query->len;
	data = query->table->t_node.bh->b_data + query->off;

	query->table = NULL; /* apfs_free_query() must not release the table */

fail:
	apfs_free_query(sb, query);
	return data;
}

/**
 * apfs_cat_resolve - Resolve a catalog key into an inode number
 * @sb:		filesystem superblock
 * @key:	catalog key (for a key record)
 *
 * Returns the inode number (cnid of the file record), or 0 in case of
 * failure.
 */
u64 apfs_cat_resolve(struct super_block *sb, struct apfs_key *key)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_query *query;
	struct apfs_dentry *data;
	char *raw;
	u64 cnid = 0;

	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query)
		return 0;
	query->key = key;
	query->flags |= APFS_QUERY_CAT | APFS_QUERY_EXACT;

	if (apfs_btree_query(sb, &query))
		goto fail;

	raw = query->table->t_node.bh->b_data + query->off;
	data = (struct apfs_dentry *)raw;
	switch (query->len) {
	case 0x22: /* hard link */
	case 0x12:
		cnid = le64_to_cpu(data->d_cnid);
		break;
	default:
		/* Corrupted filesystem? Or something new? */
		break;
	}

fail:
	apfs_free_query(sb, query);
	return cnid;
}

/**
 * apfs_btom_read_table - Find and read a table from a b-tree
 * @id:		node id for the seeked table
 *
 * Returns NULL is case of failure, otherwise a pointer to the resulting
 * apfs_table structure.
 */
struct apfs_table *apfs_btom_read_table(struct super_block *sb, u64 id)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_table *result = NULL;
	struct apfs_query *query;
	struct apfs_btom_data *data;
	struct apfs_key *key;
	char *raw;
	u64 block;

	query = apfs_alloc_query(sbi->s_btom_root, NULL /* parent */);
	if (!query)
		return NULL;

	key = kmalloc(sizeof(*key), GFP_KERNEL);
	if (!key)
		goto fail;
	apfs_init_key(0 /* type */, id, NULL /* name */, 0 /* namelen */,
		      0 /* offset */, key);
	query->key = key;
	query->flags |= APFS_QUERY_BTOM | APFS_QUERY_EXACT;

	if (apfs_btree_query(sb, &query))
		goto fail;

	if (query->len != sizeof(*data)) /* Invalid filesystem */
		goto fail;
	raw = query->table->t_node.bh->b_data;
	data = (struct apfs_btom_data *)(raw + query->off);
	block = le64_to_cpu(data->block);

	result = apfs_read_table(sb, block);
	if (!result)
		goto fail;
	if (result->t_node.node_id != id)
		apfs_debug(sb, "corrupt b-tree");

fail:
	kfree(key);
	apfs_free_query(sb, query);
	return result;
}
