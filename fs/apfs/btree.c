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
 * apfs_key_has_name - Check if a key has a name
 * @key: the catalog key
 *
 * Returns true if the key should have a name string inside, false otherwise.
 */
static inline bool apfs_key_has_name(struct apfs_cat_key *key)
{
	int type = apfs_cat_type(key);

	return type == APFS_RT_KEY || type == APFS_RT_NAMED_ATTR;
}

/**
 * apfs_cat_keycmp - Compare two catalog keys
 * @k1, @k2: keys to compare
 *
 * returns   0 if @k1 and @k2 are equal
 *	   < 0 if @k1 comes before @k2 in the btree
 *	   > 0 if @k1 comes after @k2 in the btree
 *
 * If the catalog keys are of a type that holds filenames, the caller must
 * ensure proper string termination within the block. Otherwise a crafted
 * filesystem could cause a segfault in strcasecmp().
 *
 * For now we assume filenames are in ascii. TODO: unicode support.
 */
static int apfs_cat_keycmp(struct apfs_cat_key *k1, struct apfs_cat_key *k2)
{
	u64 cnid1 = apfs_cat_cnid(k1);
	u64 cnid2 = apfs_cat_cnid(k2);
	int type1 = apfs_cat_type(k1);
	int type2 = apfs_cat_type(k2);

	if (cnid1 != cnid2)
		return cnid1 < cnid2 ? -1 : 1;
	if (type1 != type2)
		return type1 < type2 ? -1 : 1;
	if (apfs_key_has_name(k1))
		/* TODO: support case sensitive filesystems */
		return strcasecmp(k1->k_filename, k2->k_filename);
	return 0;
}



/* TODO: the next two functions need to be split, and code should be reused */

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
	struct apfs_table *root = sbi->s_cat_tree->root;
	struct apfs_table *table = root;
	struct apfs_table *btom = sbi->s_cat_tree->btom;
	int i, j;

	/*
	 * We need a maximum depth for the tree so we can't loop forever if the
	 * filesystem is damaged. 12 should be enough to map every block.
	 */
	for (i = 0; i < 12; i++) {
		bool success = false;
		u64 id = 0;

		for (j = table->t_records - 1; j >= 0; j--) {
			/* TODO: this is slow, do bisection instead */
			int len, off;
			int cmp;
			char *raw = table->t_node.bh->b_data;
			struct apfs_cat_key *this_key;
			struct apfs_cat_keyrec *data;

			len = apfs_table_locate_key(table, j, &off);
			if (len == 0) /* Corrupt filesystem */
				break;
			this_key = (struct apfs_cat_key *)(raw + off);

			if (apfs_key_has_name(this_key) &&
			    *(raw + off + len - 1) != 0)
				/* Invalid fs: name has no null termination */
				break;

			cmp = apfs_cat_keycmp(this_key, key);
			if (cmp <= 0) {
				/*
				 * In an index node the records are in order,
				 * so the one we want is the last among those
				 * with a key below our target.
				 */
				len = apfs_table_locate_data(table, j, &off);
				if (len == 0x08) {
					/*
					 * This is an index node; the data is
					 * the id of the child table to search
					 * next.
					 *
					 * TODO: better way to tell apart index
					 * and leaf nodes?
					 */
					id = le64_to_cpup((__le64 *)
								(raw + off));
					break;
				}

				/*
				 * We have reached a leaf node. Leaf records
				 * don't seem to be stored in order like the
				 * others, so we need to keep going if this
				 * is not the one we wanted.
				 */
				if (apfs_cat_type(this_key) != APFS_RT_KEY)
					continue;
				data = (struct apfs_cat_keyrec *)(raw + off);
				switch (len) {
				case 0x22:
					/*
					 * These records have something to do
					 * with hard links. We ignore them for
					 * now. TODO: figure this out.
					 */
					continue;
				case 0x12:
					if (cmp != 0)
						continue;
					id = le64_to_cpu(data->d_cnid);
					success = true;
					break;
				default:
					/* Unknown, ignore */
					continue;
				}
				/* We found the record */
				break;
			}
		}
		if (table != root)
			apfs_release_table(table);
		if (id == 0 || success)
			return id;

		/* Keep going and search the child */
		table = apfs_btom_read_table(btom, id);
		if (!table)
			return 0;
	}

	/* This should never be reached with a valid filesystem */
	apfs_release_table(table);
	return 0;
}

/**
 * apfs_btom_read_table - Find and read a table from a b-tree
 * @btom:	b-tree object map
 * @id:		node id for the seeked table
 *
 * Returns NULL is case of failure, otherwise a pointer to the resulting
 * apfs_table structure.
 */
struct apfs_table *apfs_btom_read_table(struct apfs_table *btom, u64 id)
{
	struct super_block *sb = btom->t_node.sb;
	struct apfs_table *table = btom;
	int i, j;

	/*
	 * We need a maximum depth for the btom so we can't loop forever if the
	 * filesystem is damaged. 12 should be enough to map every block.
	 */
	for (i = 0; i < 12; i++) {
		u64 block = 0;

		for (j = table->t_records - 1; j >= 0; j--) {
			/* TODO: this is slow, do bisection instead */
			int len, off;
			char *raw = table->t_node.bh->b_data;
			struct apfs_btom_key *key;
			struct apfs_btom_data *data;

			len = apfs_table_locate_key(table, j, &off);
			if (len != sizeof(*key)) /* Filesystem is corrupted */
				break;
			key = (struct apfs_btom_key *)(raw + off);

			if (le64_to_cpu(key->block_id) <= id) {
				/*
				 * Since the records are in order, the one we
				 * want is the last among those with an id
				 * below our target.
				 */
				len = apfs_table_locate_data(table, j, &off);
				switch (len) {
				case 0x10:
					data = (struct apfs_btom_data *)
								(raw + off);
					block = le64_to_cpu(data->child_blk);
					break;
				case 0x08:
					block = le64_to_cpup((__le64 *)
								(raw + off));
					break;
				default:
					/* Filesystem is corrupted */
					break;
				}
				/*
				 * This was the record we wanted, so we are
				 * done with this table. If block is still 0
				 * by now that means the search failed.
				 */
				break;
			}
		}
		if (table != btom)
			apfs_release_table(table);
		if (block == 0)
			return NULL;
		table = apfs_read_table(sb, block);
		if (!table)
			return NULL;
		if (table->t_node.node_id == id) {
			/*
			 * TODO: we need a better way to tell if we're done,
			 * because in theory this could happen by pure chance.
			 */
			return table;
		}
	}

	/* This should never be reached with a valid filesystem */
	apfs_release_table(table);
	return NULL;
}
