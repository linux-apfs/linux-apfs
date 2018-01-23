// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/table.c
 *
 * Copyright (C) 2018 Ernesto A. Fernandez <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/slab.h>
#include <linux/buffer_head.h>
#include "apfs.h"

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
		apfs_msg(sb, KERN_ERR, "unable to read table");
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
	return table;

release_bh:
	brelse(bh);
	return table;
}

/**
 * apfs_release_table - Release a table structure
 *
 * This function is barely a draft, since it simply frees the table and
 * ignores other possible users.
 */
void apfs_release_table(struct apfs_table *table)
{
	brelse(table->t_node.bh);
	kfree(table);
}

/**
 * apfs_table_locate_key - Locate the key of a table entry
 * @table:	table node to be searched
 * @index:	number of the entry to locate
 * @off:	on return will hold the offset in the block
 *
 * Returns the length of the key, 0 if @index is out of bounds.
 */
int apfs_table_locate_key(struct apfs_table *table, int index, int *off)
{
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
	return len;
}

/**
 * apfs_table_locate_data - Locate the data of a table entry
 * @table:	table node to be searched
 * @index:	number of the entry to locate
 * @off:	on return will hold the offset in the block
 *
 * Returns the length of the data, 0 if @index is out of bounds.
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
	return len;
}
