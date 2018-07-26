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
 * Structure of the keys in the B-Tree Object Map table
 */
struct apfs_btom_key {
	__le64 block_id;	/* Block id of the child */
	__le64 checkpoint_id;
} __attribute__ ((__packed__));

/*
 * The name length in the catalog key counts the terminating null byte.
 *
 * TODO: It seems that the catalog keys use 10 bits to store the length
 * instead of 8, so this could be wrong.
 */
#define APFS_NAME_LEN		254

#define APFS_ROOT_CNID		2 /* Root directory cnid */

/* Catalog node record types */
#define APFS_RT_INODE		0x30
#define APFS_RT_NAMED_ATTR	0x40
#define APFS_RT_HARDLINK	0x50
#define APFS_RT_EXTENT_STATUS	0x60 /* Shows the file object has records */
#define APFS_RT_UNKNOWN		0x70
#define APFS_RT_EXTENT		0x80
#define APFS_RT_DENTRY		0x90

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

/*
 * Structure of the extent keys in the catalog tables.
 */
struct apfs_extent_key {
	__le64 cnid;	/* Inode number, with 0x80 in the last byte */
	__le64 off;	/* Offset of the extent in the file */
} __attribute__ ((__packed__));

/*
 * Structure of catalog keys that don't include a name (other than extents).
 */
struct apfs_anon_key {
	__le64 cnid;	/* Id of the record, with the type in the last 8 bits */
} __attribute__ ((__packed__));

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

extern int apfs_keycmp(struct apfs_key *k1, struct apfs_key *k2);
extern int apfs_read_cat_key(void *raw, int size, struct apfs_key *key);
extern int apfs_read_btom_key(void *raw, int size, struct apfs_key *key);
extern int apfs_read_vol_key(void *raw, int size, struct apfs_key *key);
extern void apfs_init_key(int type, u64 id, const char *name, int namelen,
			  u64 offset, struct apfs_key *key);

#endif	/* _APFS_KEY_H */
