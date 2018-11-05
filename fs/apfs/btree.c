// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/btree.c
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/buffer_head.h>
#include <linux/slab.h>
#include "apfs.h"
#include "btree.h"
#include "dir.h"
#include "key.h"
#include "message.h"
#include "super.h"
#include "table.h"

/**
 * apfs_omap_lookup_block - Find the block number of a b-tree node from its id
 * @sb:		filesystem superblock
 * @tbl:	Root of the object map to be searched
 * @id:		id of the node
 * @block:	on return, the found block number
 *
 * Returns 0 on success or a negative error code in case of failure.
 */
int apfs_omap_lookup_block(struct super_block *sb, struct apfs_table *tbl,
			   u64 id, u64 *block)
{
	struct apfs_query *query;
	struct apfs_key *key;
	struct apfs_omap_val *data;
	char *raw;
	int ret = 0;

	query = apfs_alloc_query(tbl, NULL /* parent */);
	if (!query)
		return -ENOMEM;

	key = kmalloc(sizeof(*key), GFP_KERNEL);
	if (!key) {
		ret = -ENOMEM;
		goto fail;
	}

	apfs_init_key(0 /* type */, id, NULL /* name */, 0 /* namelen */,
		      0 /* offset */, key);
	query->key = key;
	query->flags |= APFS_QUERY_OMAP | APFS_QUERY_EXACT;

	ret = apfs_btree_query(sb, &query);
	if (ret)
		goto fail;

	if (query->len != sizeof(*data)) {
		apfs_alert(sb, "bad object map leaf block: 0x%llx",
			   query->table->t_node.block_nr);
		ret = -EFSCORRUPTED;
		goto fail;
	}

	raw = query->table->t_node.bh->b_data;
	data = (struct apfs_omap_val *)(raw + query->off);
	*block = le64_to_cpu(data->ov_paddr);

fail:
	kfree(key);
	apfs_free_query(sb, query);
	return ret;
}

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
	struct apfs_table *omap = sbi->s_omap_root;

	kfree(query->curr);
	if (query->table != root && query->table != omap)
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
	struct apfs_table *omap = sbi->s_omap_root;
	struct apfs_table *table;
	struct apfs_query *parent;
	char *raw;
	u64 child_id, child_blk;
	int err;

next_node:
	if ((*query)->depth >= 12) {
		/*
		 * We need a maximum depth for the tree so we can't loop
		 * forever if the filesystem is damaged. 12 should be more
		 * than enough to map every block.
		 */
		apfs_alert(sb, "b-tree is corrupted");
		return -EFSCORRUPTED;
	}

	err = apfs_table_query(sb, *query);
	if (err == -EAGAIN) {
		if (!(*query)->parent) /* We are at the root of the tree */
			return -ENODATA;

		/* Move back up one level and continue the query */
		parent = (*query)->parent;
		(*query)->parent = NULL; /* Don't free the parent */
		apfs_free_query(sb, *query);
		*query = parent;
		/* TODO: a crafted fs could have us spinning for too long */
		goto next_node;
	}
	if (err)
		return err;
	if (apfs_table_is_leaf((*query)->table)) /* All done */
		return 0;

	/* The data on an index node is the id of the child */
	if ((*query)->len != 8) {
		apfs_alert(sb, "bad index block: 0x%llx",
			   (*query)->table->t_node.block_nr);
		return -EFSCORRUPTED;
	}

	raw = (*query)->table->t_node.bh->b_data;
	child_id = le64_to_cpup((__le64 *)(raw + (*query)->off));

	/*
	 * The omap maps a node id into a block number. The nodes
	 * of the omap itself do not need this translation.
	 */
	if ((*query)->flags & APFS_QUERY_OMAP) {
		child_blk = child_id;
	} else {
		/*
		 * we are always performing lookup from omap root. Might
		 * need improvement in the future.
		 */
		err = apfs_omap_lookup_block(sb, sbi->s_omap_root,
					     child_id, &child_blk);
		if (err)
			return err;
	}

	/* Now go a level deeper and search the child */
	table = apfs_read_table(sb, child_blk);
	if (!table)
		return -ENOMEM;
	if (table->t_node.node_id != child_id)
		apfs_debug(sb, "corrupt b-tree");

	if ((*query)->flags & APFS_QUERY_MULTIPLE) {
		/*
		 * We are looking for multiple entries, so we must remember
		 * the parent table and index to continue the search later.
		 */
		*query = apfs_alloc_query(table, *query);
	} else {
		/* Reuse the same query structure to search the child */
		if ((*query)->table != root && (*query)->table != omap)
			apfs_release_table((*query)->table);
		(*query)->table = table;
		(*query)->index = table->t_records;
		(*query)->depth++;
	}
	goto next_node;
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
 * @ino:	on return, the inode number found
 *
 * Returns 0 and the inode number on success; Otherwise, return the
 * appropriate error code.
 */
int apfs_cat_resolve(struct super_block *sb, struct apfs_key *key, u64 *ino)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_query *query;
	struct apfs_drec_val *data;
	char *raw;
	int err = 0;

	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query)
		return -ENOMEM;
	query->key = key;
	query->flags |= APFS_QUERY_CAT | APFS_QUERY_EXACT;

	err = apfs_btree_query(sb, &query);
	if (err)
		goto out;

	raw = query->table->t_node.bh->b_data + query->off;
	data = (struct apfs_drec_val *)raw;
	if (query->len >= sizeof(*data))
		*ino = le64_to_cpu(data->file_id);
	else
		err = -EFSCORRUPTED;

out:
	apfs_free_query(sb, query);
	return err;
}

/**
 * apfs_omap_read_table - Find and read a table from a b-tree
 * @id:		node id for the seeked table
 *
 * Returns NULL is case of failure, otherwise a pointer to the resulting
 * apfs_table structure.
 */
struct apfs_table *apfs_omap_read_table(struct super_block *sb, u64 id)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_table *result;
	u64 block;

	if (apfs_omap_lookup_block(sb, sbi->s_omap_root, id, &block))
		return NULL;

	result = apfs_read_table(sb, block);
	if (!result)
		return NULL;

	if (result->t_node.node_id != id)
		apfs_debug(sb, "corrupt b-tree");

	return result;
}
