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

/*
 * The name length in the catalog key counts the terminating null byte.
 *
 * TODO: It seems that the catalog keys use 10 bits to store the length
 * instead of 8, so this could be wrong.
 */
#define APFS_NAME_LEN		254

#define APFS_ROOT_CNID		2 /* Root directory cnid */

/*
 * Structure of the dentry keys in the catalog tables.
 */
struct apfs_dentry_key {
	/* Parent directory cnid, with record type 0x90 in the last 8 bits */
	__le64 parent;
	/* Hash of the normalized filename, mixing the crc32c and the length */
	__le32 hash;
	/* Filename, with no normalization */
	char name[0];
} __attribute__ ((__packed__));

/*
 * Structure of the keys for named attributes in the catalog tables.
 */
struct apfs_xattr_key {
	/* Inode the xattr belongs to, with record type 0x40 in the last byte */
	__le64 cnid;
	/* Length of the attribute name */
	__le16 length;
	/* Attribute name */
	char name[0];
} __attribute__ ((__packed__));

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

/*
 * Structure of the extent keys in the catalog tables.
 */
struct apfs_extent_key {
	__le64 cnid;	/* Inode number, with 0x80 in the last byte */
	__le64 off;	/* Offset of the extent in the file */
} __attribute__ ((__packed__));

/* Bit masks for the 'obj_id_and_type' field of a key header */
#define APFS_OBJ_ID_MASK		0x0fffffffffffffffULL
#define APFS_OBJ_TYPE_MASK		0xf000000000000000ULL
#define APFS_OBJ_TYPE_SHIFT		60

/* Key header for filesystem-object keys */
struct apfs_key_header {
	__le64 obj_id_and_type;
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
