/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_KEY_H
#define _APFS_KEY_H

#include <linux/types.h>
#include <asm/byteorder.h>
#include "apfs_raw.h"

struct super_block;

/*
 * In-memory representation of a key, as relevant for a b-tree query.
 */
struct apfs_key {
	u64		id;
	u64		number;	/* Extent offset, name hash or transaction id */
	const char	*name;	/* On-disk name string */
	u8		type;	/* Record type (0 for the omap) */
};

/**
 * apfs_init_free_queue_key - Initialize an in-memory key for a free queue query
 * @xid:	transaction id
 * @paddr:	block number
 * @key:	apfs_key structure to initialize
 */
static inline void apfs_init_free_queue_key(u64 xid, u64 paddr,
					    struct apfs_key *key)
{
	key->id = xid;
	key->type = 0;
	key->number = paddr;
	key->name = NULL;
}

/**
 * apfs_init_omap_key - Initialize an in-memory key for an omap query
 * @oid:	object id
 * @xid:	latest transaction id
 * @key:	apfs_key structure to initialize
 */
static inline void apfs_init_omap_key(u64 oid, u64 xid, struct apfs_key *key)
{
	key->id = oid;
	key->type = 0;
	key->number = xid;
	key->name = NULL;
}

/**
 * apfs_init_inode_key - Initialize an in-memory key for an inode query
 * @ino:	inode number
 * @key:	apfs_key structure to initialize
 */
static inline void apfs_init_inode_key(u64 ino, struct apfs_key *key)
{
	key->id = ino;
	key->type = APFS_TYPE_INODE;
	key->number = 0;
	key->name = NULL;
}

/**
 * apfs_init_file_extent_key - Initialize an in-memory key for an extent query
 * @id:		extent id
 * @offset:	logical address (0 for a multiple query)
 * @key:	apfs_key structure to initialize
 */
static inline void apfs_init_file_extent_key(u64 id, u64 offset,
					     struct apfs_key *key)
{
	key->id = id;
	key->type = APFS_TYPE_FILE_EXTENT;
	key->number = offset;
	key->name = NULL;
}

/**
 * apfs_init_sibling_link_key - Initialize an in-memory key for a sibling query
 * @ino:	inode number
 * @id:		sibling id
 * @key:	apfs_key structure to initialize
 */
static inline void apfs_init_sibling_link_key(u64 ino, u64 id,
					      struct apfs_key *key)
{
	key->id = ino;
	key->type = APFS_TYPE_SIBLING_LINK;
	key->number = id; /* Only guessing */
	key->name = NULL;
}

/**
 * apfs_init_sibling_map_key - Initialize in-memory key for a sibling map query
 * @id:		sibling id
 * @key:	apfs_key structure to initialize
 */
static inline void apfs_init_sibling_map_key(u64 id, struct apfs_key *key)
{
	key->id = id;
	key->type = APFS_TYPE_SIBLING_MAP;
	key->number = 0;
	key->name = NULL;
}

extern void apfs_init_drec_hashed_key(struct super_block *sb, u64 ino,
				      const char *name, struct apfs_key *key);

/**
 * apfs_init_xattr_key - Initialize an in-memory key for a xattr query
 * @ino:	inode number of the parent file
 * @name:	xattr name (NULL for a multiple query)
 * @key:	apfs_key structure to initialize
 */
static inline void apfs_init_xattr_key(u64 ino, const char *name,
				       struct apfs_key *key)
{
	key->id = ino;
	key->type = APFS_TYPE_XATTR;
	key->number = 0;
	key->name = name;
}

/**
 * apfs_key_set_hdr - Set the header for a raw catalog key
 * @type:	record type
 * @id:		record id
 * @key:	the key to initialize
 */
static inline void apfs_key_set_hdr(u64 type, u64 id, void *key)
{
	struct apfs_key_header *hdr = key;

	hdr->obj_id_and_type = cpu_to_le64(id | type << APFS_OBJ_TYPE_SHIFT);
}

extern int apfs_filename_cmp(struct super_block *sb,
			     const char *name1, const char *name2);
extern int apfs_keycmp(struct super_block *sb,
		       struct apfs_key *k1, struct apfs_key *k2);
extern int apfs_read_cat_key(void *raw, int size, struct apfs_key *key);
extern int apfs_read_free_queue_key(void *raw, int size, struct apfs_key *key);
extern int apfs_read_omap_key(void *raw, int size, struct apfs_key *key);

#endif	/* _APFS_KEY_H */
