/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_NODE_H
#define _APFS_NODE_H

#include <linux/kref.h>
#include <linux/types.h>
#include "apfs_raw.h"
#include "object.h"

struct apfs_query;

/* Constants used in managing the size of a node's table of contents */
#define APFS_BTREE_TOC_ENTRY_INCREMENT	8
#define APFS_BTREE_TOC_ENTRY_MAX_UNUSED	(2 * BTREE_TOC_ENTRY_INCREMENT)

/*
 * In-memory representation of an APFS node
 */
struct apfs_node {
	u16 flags;		/* Node flags */
	u32 records;		/* Number of records in the node */

	int key;		/* Offset of the key area in the block */
	int free;		/* Offset of the free area in the block */
	int data;		/* Offset of the data area in the block */

	int key_free_list_len;	/* Length of the fragmented free key space */
	int val_free_list_len;	/* Length of the fragmented free value space */

	struct apfs_object object; /* Object holding the node */

	struct kref refcount;
};

/**
 * apfs_node_is_leaf - Check if a b-tree node is a leaf
 * @node: the node to check
 */
static inline bool apfs_node_is_leaf(struct apfs_node *node)
{
	return (node->flags & APFS_BTNODE_LEAF) != 0;
}

/**
 * apfs_node_is_root - Check if a b-tree node is the root
 * @node: the node to check
 */
static inline bool apfs_node_is_root(struct apfs_node *node)
{
	return (node->flags & APFS_BTNODE_ROOT) != 0;
}

/**
 * apfs_node_has_fixed_kv_size - Check if a b-tree node has fixed key/value
 * sizes
 * @node: the node to check
 */
static inline bool apfs_node_has_fixed_kv_size(struct apfs_node *node)
{
	return (node->flags & APFS_BTNODE_FIXED_KV_SIZE) != 0;
}

extern struct apfs_node *apfs_read_node(struct super_block *sb, u64 oid,
					u32 storage, bool write);
extern void apfs_update_node(struct apfs_node *node);
extern int apfs_delete_node(struct apfs_query *query);
extern int apfs_node_query(struct super_block *sb, struct apfs_query *query);
extern int apfs_bno_from_query(struct apfs_query *query, u64 *bno);
extern void apfs_create_toc_entry(struct apfs_query *query);
extern int apfs_node_split(struct apfs_query *query);
extern int apfs_node_locate_key(struct apfs_node *node, int index, int *off);

extern void apfs_node_get(struct apfs_node *node);
extern void apfs_node_put(struct apfs_node *node);

#endif	/* _APFS_NODE_H */
