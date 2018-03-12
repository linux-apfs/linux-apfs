// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/btree.c
 *
 * Copyright (C) 2018 Ernesto A. Fernandez <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/buffer_head.h>
#include "apfs.h"

/**
 * apfs_cat_type - Read the record type of a catalog key
 * @key: the catalog key
 *
 * The record type is stored in the last byte of the k_cnid
 * field; returns that value.
 */
static inline int apfs_cat_type(struct apfs_cat_key *key)
{
	return ((unsigned char *)&key->k_cnid)[7];
}

/**
 * apfs_cat_cnid - Read the cnid value on a catalog key
 * @key: the catalog key
 *
 * The cnid value shares the k_cnid field with the record type. This function
 * masks that part away and returns the result.
 */
static inline u64 apfs_cat_cnid(struct apfs_cat_key *key)
{
	return le64_to_cpu(key->k_cnid) & (0x00FFFFFFFFFFFFFFULL);
}

/**
 * apfs_cat_anon_keycmp - Compare two catalog keys, ignoring the filenames
 * @k1, @k2:	pointers to the keys to compare, both of type apfs_cat_key
 * @len:	length of @k1
 *
 * returns   0 if @k1 and @k2 are equal
 *	   < 0 if @k1 comes before @k2 in the btree
 *	   > 0 if @k1 comes after @k2 in the btree (or in case of error)
 */
int apfs_cat_anon_keycmp(void *k1, void *k2, int len)
{
	u64 cnid1;
	u64 cnid2;
	int type1;
	int type2;

	if (len < 8) {
		/*
		 * Invalid filesystem. We choose a positive return value
		 * because that will cause apfs_table_query() to fail.
		 */
		return 1;
	}

	cnid1 = apfs_cat_cnid(k1);
	cnid2 = apfs_cat_cnid(k2);
	if (cnid1 != cnid2)
		return cnid1 < cnid2 ? -1 : 1;

	type1 = apfs_cat_type(k1);
	type2 = apfs_cat_type(k2);
	if (type1 != type2)
		return type1 < type2 ? -1 : 1;

	return 0;
}

/**
 * apfs_cat_keycmp - Compare two catalog keys
 * @k1, @k2:	pointers to the keys to compare, both of type apfs_cat_key
 * @len:	length of @k1
 *
 * returns   0 if @k1 and @k2 are equal
 *	   < 0 if @k1 comes before @k2 in the btree
 *	   > 0 if @k1 comes after @k2 in the btree (or in case of error)
 *
 * For now we assume filenames are in ascii. TODO: unicode support.
 */
int apfs_cat_keycmp(void *k1, void *k2, int len)
{
	int name_off;
	int ret;

	ret = apfs_cat_anon_keycmp(k1, k2, len);
	if (ret)
		return ret;

	switch (apfs_cat_type(k1)) {
	case APFS_RT_KEY:
		/* Three mystery bytes before the name */
		name_off = 3;
		break;
	case APFS_RT_NAMED_ATTR:
		/* One mystery byte before the name */
		name_off = 1;
		break;
	default:
		/* No name string at all */
		return 0;
	}

	if (len < sizeof(struct apfs_cat_key) + name_off + 1) {
		/* The filename must have at least one char */
		return 1;
	}
	if (*((char *)k1 + len - 1) != 0) {
		/* strcasecmp() expects proper NULL termination */
		return 1;
	}

	/* TODO: support case sensitive filesystems */
	return strcasecmp(((struct apfs_cat_key *)k1)->k_name + name_off,
			  ((struct apfs_cat_key *)k2)->k_name + name_off);
}

/**
 * apfs_cmp64 - Trivial function to compare 64 bit integers
 * @k1, @k2:	pointers to the integers. @k1 is __le64, @k2 is u64
 * @len:	length of the whole key @k1 (we only compare the first 64 bits)
 *
 * returns   0 if @k1 == @k2
 *         < 0 if @k1 < @k2
 *         > 0 if @k1 > @k2 (or in case of error)
 *
 * This function exists only to serve as a parameter in calls to
 * apfs_table_query().
 */
int apfs_cmp64(void *k1, void *k2, int len)
{
	if (len < sizeof(u64)) {
		/*
		 * Invalid filesystem. We choose a positive return value
		 * because that will cause apfs_table_query() to fail.
		 */
		return 1;
	}
	return le64_to_cpup((__le64 *)k1) - *(u64 *)k2;
}

/**
 * apfs_node_is_leaf - Check if a b-tree node is a leaf
 * @table: the node to check
 *
 * This function would probably not be necessary if I just gave a name to the
 * magical constant 2 that it uses, but I'm not sure of its meaning.
 */
static inline bool apfs_node_is_leaf(struct apfs_table *table)
{
	return (table->t_type & 2) != 0;
}

/**
 * apfs_node_is_btom - Check if a b-tree node belongs to the btom
 * @table: the node to check
 *
 * This function would probably not be necessary if I just gave a name to the
 * magical constant 4 that it uses, but I'm not sure of its meaning.
 */
static inline bool apfs_node_is_btom(struct apfs_table *table)
{
	return (table->t_type & 4) != 0;
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

	query = kmalloc(sizeof(*query), GFP_KERNEL);
	if (!query)
		return NULL;

	query->table = table;
	query->key = parent ? parent->key : NULL;
	query->flags = parent ? parent->flags & ~APFS_QUERY_DONE : 0;
	query->parent = parent;
	query->cmp = parent ? parent->cmp : NULL;
	/* Start the search with the last record and go backwards */
	query->index = table->t_records;
	query->depth = parent ? parent->depth + 1 : 0;

	return query;
}

/**
 * apfs_free_query - Free a query structure
 * @sb:		filesystem superblock
 * @query:	query to free
 *
 * Also frees the table if it's not the root of a b-tree, and the parent query
 * if it is kept. If a search key was allocated, the caller may still need to
 * free that.
 */
void apfs_free_query(struct super_block *sb, struct apfs_query *query)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_table *root = sbi->s_cat_tree->root;
	struct apfs_table *btom = sbi->s_cat_tree->btom;

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
	struct apfs_table *root = sbi->s_cat_tree->root;
	struct apfs_table *btom = sbi->s_cat_tree->btom;
	struct apfs_table *table;
	struct apfs_query *btom_query;
	struct apfs_query *parent;
	struct apfs_btom_data *data;
	char *raw = (*query)->table->t_node.bh->b_data;
	u64 child = 0;
	bool ordered = true;
	int err;

	if ((*query)->depth >= 12) {
		/*
		 * We need a maximum depth for the tree so we can't loop
		 * forever if the filesystem is damaged. 12 should be more
		 * than enough to map every block.
		 */
		return -EINVAL;
	}

	if (apfs_node_is_leaf((*query)->table) &&
	    !apfs_node_is_btom((*query)->table)) {
		/* The leaves of a catalog tree are not ordered */
		ordered = false;
	}
	err = apfs_table_query(*query, ordered);
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
	if (apfs_node_is_leaf((*query)->table)) /* All done */
		return 0;
	if (apfs_node_is_btom((*query)->table)) {
		/* The data on a btom index node is the address of the child */
		if ((*query)->len != 8)
			return -EINVAL;
		child = le64_to_cpup((__le64 *)(raw + (*query)->off));
	} else {
		/*
		 * The data on an index node is the id of the table
		 * to search next; we must query the btom to find its
		 * block number.
		 */
		if ((*query)->len != 8)
			return -EINVAL;
		child = le64_to_cpup((__le64 *)(raw + (*query)->off));
		btom_query = apfs_alloc_query(btom, NULL /* parent */);
		if (!btom_query)
			return -ENOMEM;
		btom_query->key = &child;
		btom_query->cmp = apfs_cmp64;
		err = apfs_btree_query(sb, &btom_query);
		if (err)
			goto fail;
		raw = btom_query->table->t_node.bh->b_data;
		if (btom_query->len != sizeof(*data)) {
			err = -EINVAL;
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
void *apfs_cat_get_data(struct super_block *sb, struct apfs_cat_key *key,
			int *length, struct apfs_table **table)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_query *query;
	void *data = NULL;

	query = apfs_alloc_query(sbi->s_cat_tree->root, NULL /* parent */);
	if (!query)
		return NULL;
	query->key = key;
	query->cmp = apfs_cat_keycmp;

	if (apfs_btree_query(sb, &query))
		goto fail;

	*table = query->table;
	*length = query->len;
	data = query->table->t_node.bh->b_data + query->off;

	kfree(query);
	return data;

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
u64 apfs_cat_resolve(struct super_block *sb, struct apfs_cat_key *key)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_query *query;
	struct apfs_cat_keyrec *data;
	char *raw;
	u64 cnid = 0;

	query = apfs_alloc_query(sbi->s_cat_tree->root, NULL /* parent */);
	if (!query)
		return 0;
	query->key = key;
	query->cmp = apfs_cat_keycmp;

	if (apfs_btree_query(sb, &query))
		goto fail;

	raw = query->table->t_node.bh->b_data + query->off;
	data = (struct apfs_cat_keyrec *)raw;
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
	char *raw;
	u64 block;

	query = apfs_alloc_query(sbi->s_cat_tree->btom, NULL /* parent */);
	if (!query)
		return NULL;
	query->key = &id;
	query->cmp = apfs_cmp64;

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
	if (result->t_node.node_id != id) /* TODO: check this only on debug */
		apfs_msg(sb, KERN_ERR, "corrupt b-tree");

fail:
	apfs_free_query(sb, query);
	return result;
}
