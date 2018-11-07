/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/key.h
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_KEY_H
#define _APFS_KEY_H

#include <linux/types.h>

/*
 * Structure of a key in an object map B-tree
 */
struct apfs_omap_key {
	__le64 ok_oid;
	__le64 ok_xid;
} __packed;

/* Catalog records types */
enum {
	APFS_TYPE_ANY			= 0,
	APFS_TYPE_SNAP_METADATA		= 1,
	APFS_TYPE_EXTENT		= 2,
	APFS_TYPE_INODE			= 3,
	APFS_TYPE_XATTR			= 4,
	APFS_TYPE_SIBLING_LINK		= 5,
	APFS_TYPE_DSTREAM_ID		= 6,
	APFS_TYPE_CRYPTO_STATE		= 7,
	APFS_TYPE_FILE_EXTENT		= 8,
	APFS_TYPE_DIR_REC		= 9,
	APFS_TYPE_DIR_STATS		= 10,
	APFS_TYPE_SNAP_NAME		= 11,
	APFS_TYPE_SIBLING_MAP		= 12,
	APFS_TYPE_MAX_VALID		= 12,
	APFS_TYPE_MAX			= 15,
	APFS_TYPE_INVALID		= 15,
};

/* Bit masks for the 'obj_id_and_type' field of a key header */
#define APFS_OBJ_ID_MASK		0x0fffffffffffffffULL
#define APFS_OBJ_TYPE_MASK		0xf000000000000000ULL
#define APFS_OBJ_TYPE_SHIFT		60

/* Key header for filesystem-object keys */
struct apfs_key_header {
	__le64 obj_id_and_type;
} __packed;

/*
 * Structure of the key for an inode record
 */
struct apfs_inode_key {
	struct apfs_key_header hdr;
} __packed;

/*
 * Structure of the key for a file extent record
 */
struct apfs_file_extent_key {
	struct apfs_key_header hdr;
	__le64 logical_addr;
} __packed;

/*
 * Structure of the key for a data stream record
 */
struct apfs_dstream_id_key {
	struct apfs_key_header hdr;
} __packed;

/* Bit masks for the 'name_len_and_hash' field of a directory entry */
#define APFS_DREC_LEN_MASK	0x000003ff
#define APFS_DREC_HASH_MASK	0xfffff400
#define APFS_DREC_HASH_SHIFT	10

/* The name length in the catalog key counts the terminating null byte. */
#define APFS_NAME_LEN		(APFS_DREC_LEN_MASK - 1)

/* Bit masks for the 'type' field of a directory entry */
enum {
	APFS_DREC_TYPE_MASK	= 0x000f,
	APFS_DREC_RESERVED_10	= 0x0010
};

/*
 * Structure of the key for a directory entry, including a precomputed
 * hash of its name
 */
struct apfs_drec_hashed_key {
	struct apfs_key_header hdr;
	__le32 name_len_and_hash;
	u8 name[0];
} __packed;

/*
 * Structure of the key for an extended attributes record
 */
struct apfs_xattr_key {
	struct apfs_key_header hdr;
	__le16 name_len;
	u8 name[0];
} __packed;

/*
 * In-memory representation of a b-tree key. Many of the fields are unused for
 * any given key type, so maybe this struct should have some unions. TODO
 */
struct apfs_key {
	u64			id;
	u64			offset;		/* Extent offset in the file */
	const char		*name;		/* On-disk name string */
	int			type;		/* 0 for non-catalog keys */
	unsigned int		hash;		/* Hash of the name */
};

extern int apfs_filename_cmp(const char *name1, const char *name2);
extern int apfs_keycmp(struct apfs_key *k1, struct apfs_key *k2);
extern int apfs_read_cat_key(void *raw, int size, struct apfs_key *key);
extern int apfs_read_omap_key(void *raw, int size, struct apfs_key *key);
extern void apfs_init_key(int type, u64 id, const char *name, int namelen,
			  u64 offset, struct apfs_key *key);

#endif	/* _APFS_KEY_H */
