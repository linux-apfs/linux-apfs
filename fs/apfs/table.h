/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/table.h
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_TABLE_H
#define _APFS_TABLE_H

#include <linux/fs.h>
#include <linux/types.h>
#include "apfs.h"
#include "btree.h"

/*
 * In-memory representation of an APFS table
 */
struct apfs_table {
	u16 t_type;		/* Table type */
	u16 t_records;		/* Number of records in the table */

	int t_key;		/* Offset of the key area in the block */
	int t_free;		/* Offset of the free area in the block */
	int t_data;		/* Offset of the data area in the block */

	struct apfs_node t_node;/* Node holding the table */
};

/**
 * apfs_table_is_leaf - Check if a b-tree table is a leaf
 * @table: the table to check
 *
 * This function would probably not be necessary if I just gave a name to the
 * magical constant 2 that it uses, but I'm not sure of its meaning.
 */
static inline bool apfs_table_is_leaf(struct apfs_table *table)
{
	return (table->t_type & 2) != 0;
}

/**
 * apfs_table_is_btom - Check if a b-tree table belongs to the btom
 * @table: the table to check
 *
 * This function is no longer used, but I'm keeping it as documentation for now.
 */
static inline bool apfs_table_is_btom(struct apfs_table *table)
{
	return (table->t_type & 4) != 0;
}

/*
 * A block storing a table will have the following format, with the 0x28
 * bytes long footer only present for some of the table types.
 *
 *   +--------------+
 *   | node header  |
 *   | table header |
 *   | index        |
 *   | key area     |
 *   | free area    |
 *   | data area    |
 *   | (footer)     |
 *   +--------------+
 *
 */
struct apfs_table_raw {
/*00*/	struct apfs_node_header t_header;

/*20*/	__le16 t_type;		/* Table type, can be 0 to 7 */
	__le16 t_level;		/* Level in a b-tree. Level 0 is a leaf node */
	__le16 t_records;	/* Number of records in the table */
	__le16 unknown_1;
/*28*/	__le16 unknown_2;
	__le16 t_index_size;	/* Size in bytes of the table index */
	__le16 t_key_size;	/* Size in bytes of the table key area */
	__le16 t_free_size;	/* Size in bytes of the table free area */
	/*
	 * Some "tables" with t_records == 0 hold a __le64 record here,
	 * but in normal tables this is actually four __le16 values of
	 * unknown meaning.
	 */
/*30*/	union {
		struct {
			__le16 unknown_3;
			__le16 unknown_4;
			__le16 unknown_5;
			__le16 unknown_6;
		};
		__le64 t_single_rec;
	};
	/* What follows is the body of the table, beginning with the index */
	char t_body[0];
} __attribute__ ((__packed__));

/*
 * Structure of an index entry for table types 0 to 3. It stores both
 * position and length for the key and the data.
 */
struct apfs_index_entry_long {
	/* Offset of the key in the key section */
	__le16 key_off;
	__le16 key_len;
	/* Data offset, counting backwards from the end of the data section */
	__le16 data_off;
	__le16 data_len;
} __attribute__ ((__packed__));

/*
 * For table types 4 to 7, the keys and data are of a fixed length. In that
 * case the index entries will be shorter, as they only need to store the
 * offsets.
 */
struct apfs_index_entry_short {
	/* Offset of the key in the key section */
	__le16 key_off;
	/* Data offset, counting backwards from the end of the data section */
	__le16 data_off;
} __attribute__ ((__packed__));

extern struct apfs_table *apfs_read_table(struct super_block *sb, u64 block);
extern void apfs_release_table(struct apfs_table *table);
extern int apfs_table_locate_key(struct apfs_table *table,
				 int index, int *off);
extern int apfs_table_locate_data(struct apfs_table *table,
				  int index, int *off);
extern int apfs_table_query(struct super_block *sb, struct apfs_query *query);

#endif	/* _APFS_TABLE_H */
