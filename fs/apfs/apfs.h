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
 * Structure of the data in the B-Tree Object Map leaf tables. On the index
 * tables the only data is the 64 bit block address of the child.
 */
struct apfs_btom_data {
	__le32 unknown;
	__le32 child_size;	/* Size of the child */
	__le64 block;		/* Address of the table mapped by this record */
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

/*
 * Inode and file operations
 */

/* file.c */
extern const struct file_operations apfs_file_operations;
extern const struct inode_operations apfs_file_inode_operations;

/* namei.c */
extern const struct inode_operations apfs_dir_inode_operations;
extern const struct inode_operations apfs_special_inode_operations;

/* symlink.c */
extern const struct inode_operations apfs_symlink_inode_operations;

#endif	/* _APFS_H */
