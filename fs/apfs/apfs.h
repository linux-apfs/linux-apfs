/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/apfs.h
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_H
#define _APFS_H

#include <linux/fs.h>
#include <linux/types.h>

#define EFSCORRUPTED	EUCLEAN		/* Filesystem is corrupted */

#define APFS_DEFAULT_BLOCKSIZE	4096

/*
 * In-memory representation of an APFS node
 */
struct apfs_node {
	struct super_block *sb;
	u64 block_nr;
	u64 node_id;		/* Often the same as the block number */

	/*
	 * Buffer head containing the first block of the node. If the true
	 * blocksize of the file system is above PAGE_SIZE, then sb->blocksize
	 * should be set to PAGE_SIZE and more than one buffer head will be
	 * needed for each node. This is not yet implemented.
	 */
	struct buffer_head *bh;
};

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

/* Flags for the query structure */
#define APFS_QUERY_TREE_MASK	007	/* Which b-tree we query */
#define APFS_QUERY_BTOM		001	/* This is a b-tree object map query */
#define APFS_QUERY_CAT		002	/* This is a catalog tree query */
#define APFS_QUERY_VOL		004	/* This is a volume table query */
#define APFS_QUERY_MULTIPLE	010	/* Search for multiple matches */
#define APFS_QUERY_EXACT	020	/* Search for an exact match */
#define APFS_QUERY_DONE		040	/* The search at this level is over */

/*
 * Structure used to retrieve data from an APFS B-Tree. For now only used
 * on the calalog and the object map.
 */
struct apfs_query {
	struct apfs_table *table;	/* Table being searched */
	struct apfs_key *key;		/* What the query is looking for */

	struct apfs_key *curr;		/* Last on-disk key checked */
	struct apfs_query *parent;	/* Query for parent table */
	unsigned int flags;

	/* Set by the query on success */
	int index;			/* Index of the entry in the table */
	int key_off;			/* Offset of the key in the table */
	int key_len;			/* Length of the key */
	int off;			/* Offset of the data in the table */
	int len;			/* Length of the data */

	int depth;			/* Put a limit on recursion */
};

/*
 * This structure apparently heads every metadata block
 */
struct apfs_node_header {
/*00*/	__le64 n_checksum;	/* Fletcher checksusum */
	__le64 n_block_id;	/* Either the object-id or the block number */
/*10*/	__le64 n_checkpoint_id;
	__le16 unknown_1;	/* Possible level in the b-tree */
	__le16 unknown_2;	/* Seems always 0x4000. Perhaps a flag */
	__le16 unknown_3;	/* Often 0x0b, 0x0e and 0x0f */
	__le16 unknown_4;
} __attribute__ ((__packed__));

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
		} unknowns_3_6;
		__le64 t_single_rec;
	} t_sd;			/* Size dependent */
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

/*
 * Structure of the data in the B-Tree Object Map leaf tables. On the index
 * tables the only data is the 64 bit block address of the child.
 */
struct apfs_btom_data {
	__le32 unknown;
	__le32 child_size;	/* Size of the child */
	__le64 block;		/* Address of the table mapped by this record */
} __attribute__ ((__packed__));

/*
 * Structure of the data in the catalog tables for record type APFS_RT_KEY.
 *
 * Sometimes an extra 64-bit field will exist; this has something to do with
 * hard links. Either way, the cnid remains first.
 */
struct apfs_cat_keyrec {
	__le64 d_cnid;
	__le64 d_time;		/* Date Added */
	__le16 d_type;		/* File type */
} __attribute__ ((__packed__));

/*
 * Structure of the data in the catalog tables for record type APFS_RT_EXTENT.
 */
struct apfs_cat_extent {
	__le64	length;		/* Length of the extent, in bytes */
	__le64	block;		/* Number of the first block in the extent */
	char	unknown[8];	/* Often all zeros */
} __attribute__ ((__packed__));

/*
 * Function prototypes
 */

/* btree.c */
extern struct apfs_query *apfs_alloc_query(struct apfs_table *table,
					   struct apfs_query *parent);
extern void apfs_free_query(struct super_block *sb, struct apfs_query *query);
extern int apfs_btree_query(struct super_block *sb, struct apfs_query **query);
extern void *apfs_cat_get_data(struct super_block *sb, struct apfs_key *key,
			       int *length, struct apfs_table **table);
extern u64 apfs_cat_resolve(struct super_block *sb, struct apfs_key *key);
extern struct apfs_table *apfs_btom_read_table(struct super_block *sb, u64 id);

/* dir.c */
extern u64 apfs_inode_by_name(struct inode *dir, const struct qstr *child);

/* table.c */
extern struct apfs_table *apfs_read_table(struct super_block *sb, u64 block);
extern void apfs_release_table(struct apfs_table *table);
extern int apfs_table_locate_key(struct apfs_table *table,
				 int index, int *off);
extern int apfs_table_locate_data(struct apfs_table *table,
				  int index, int *off);
extern int apfs_table_query(struct apfs_query *query);

/*
 * Inode and file operations
 */

/* dir.c */
extern const struct file_operations apfs_dir_operations;

/* file.c */
extern const struct file_operations apfs_file_operations;
extern const struct inode_operations apfs_file_inode_operations;

/* namei.c */
extern const struct inode_operations apfs_dir_inode_operations;
extern const struct inode_operations apfs_special_inode_operations;

/* symlink.c */
extern const struct inode_operations apfs_symlink_inode_operations;

#endif	/* _APFS_H */
