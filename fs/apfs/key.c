// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/key.c
 *
 * Copyright (C) 2018 Ernesto A. Fernandez <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/crc32c.h>
#include <linux/nls.h>
#include <linux/ctype.h>
#include "apfs.h"
#include "key.h"

/**
 * apfs_cat_type - Read the record type of a catalog key
 * @key: the raw catalog key
 *
 * The record type is stored in the last byte of the cnid field; this function
 * returns that value.
 */
static inline int apfs_cat_type(void *key)
{
	return (le64_to_cpup(key) & 0xFF00000000000000ULL) >> 56;
}

/**
 * apfs_cat_cnid - Read the cnid value on a catalog key
 * @key: the raw catalog key
 *
 * The cnid value shares the its field with the record type. This function
 * masks that part away and returns the result.
 */
static inline u64 apfs_cat_cnid(void *key)
{
	return le64_to_cpup(key) & (0x00FFFFFFFFFFFFFFULL);
}


/**
 * apfs_keycmp - Compare two keys
 * @k1, @k2:	pointers to the keys to compare
 *
 * returns   0 if @k1 and @k2 are equal
 *	   < 0 if @k1 comes before @k2 in the btree
 *	   > 0 if @k1 comes after @k2 in the btree
 *
 * TODO: support case sensitive filesystems and unicode.
 */
int apfs_keycmp(struct apfs_key *k1, struct apfs_key *k2)
{
	if (k1->id != k2->id)
		return k1->id < k2->id ? -1 : 1;
	if (k1->type != k2->type)
		return k1->type < k2->type ? -1 : 1;
	if (k2->name == NULL) /* We ignore the names (if they exist) */
		return 0;
	if (k1->hash != k2->hash)
		return k1->hash < k2->hash ? -1 : 1;

	/* Only guessing, I've never seen two names with the same hash. TODO */
	return strcasecmp(k1->name, k2->name);
}

/**
 * apfs_read_cat_key - Parse an on-disk catalog key
 * @raw:	pointer to the raw key
 * @size:	size of the raw key
 * @key:	apfs_key structure to store the result
 *
 * Returns 0 on success, or a negative error code otherwise.
 */
int apfs_read_cat_key(void *raw, int size, struct apfs_key *key)
{
	if (size < 8) /* Invalid filesystem, all keys must have a type */
		return -EINVAL;
	key->type = apfs_cat_type(raw);
	key->id = apfs_cat_cnid(raw);

	switch (key->type) {
	case APFS_RT_KEY:
		if (size < sizeof(struct apfs_dentry_key) + 1 ||
		    *((char *)raw + size - 1) != 0) {
			/* Filename is empty or lacks NULL-termination */
			return -EINVAL;
		}
		key->hash = le32_to_cpu(((struct apfs_dentry_key *)raw)->hash);
		key->name = ((struct apfs_dentry_key *)raw)->name;
		break;
	case APFS_RT_NAMED_ATTR:
		if (size < sizeof(struct apfs_xattr_key) + 1 ||
		    *((char *)raw + size - 1) != 0) {
			/* xattr name is empty or lacks NULL-termination */
			return -EINVAL;
		}
		key->hash = 0; /* TODO: figure out the xattr name hash */
		key->name = ((struct apfs_xattr_key *)raw)->name;
		break;
	default:
		key->hash = 0;
		key->name = NULL;
		break;
	}

	return 0;
}

/**
 * apfs_read_btom_key - Parse an on-disk btom key
 * @raw:	pointer to the raw key
 * @size:	size of the raw key
 * @key:	apfs_key structure to store the result
 *
 * Returns 0 on success, or a negative error code otherwise.
 */
int apfs_read_btom_key(void *raw, int size, struct apfs_key *key)
{
	if (size < sizeof(struct apfs_btom_key))
		return -EINVAL;

	key->type = 0;
	key->id = le64_to_cpu(((struct apfs_btom_key *)raw)->block_id);
	key->name = NULL;
	key->hash = 0;

	return 0;
}

/**
 * apfs_read_vol_key - Parse an on-disk volume table key
 * @raw:	pointer to the raw key
 * @size:	size of the raw key
 * @key:	apfs_key structure to store the result
 *
 * Returns 0 on success, or a negative error code otherwise.
 */
int apfs_read_vol_key(void *raw, int size, struct apfs_key *key)
{
	if (size < 8) /* Invalid filesystem */
		return -EINVAL;

	key->type = 0;
	key->name = NULL;
	key->hash = 0;
	key->id = le64_to_cpup(raw);
	return 0;
}

/**
 * apfs_init_key - Initialize an in-memory key
 * @type:	type of the record
 * @id:		id for the record
 * @name:	name of the record (may be NULL)
 * @key:	apfs_key structure to initialize
 *
 * On success, @key will be ready to query for the record and 0 will be
 * returned. Otherwise, returns a negative error code. Note that the function
 * cannot fail if name == NULL.
 */
int apfs_init_key(int type, u64 id, const char *name, struct apfs_key *key)
{
	int len;
	char tmp8;
	unicode_t tmp32;
	u32 hash;

	key->type = type;
	key->id = id;
	key->name = name;
	if (name == NULL || type == APFS_RT_NAMED_ATTR) {
		/* TODO: Figure out the hashing scheme for xattr names */
		key->hash = 0;
		return 0;
	}

	len = 1; /* Count the terminating NULL */
	hash = 0xFFFFFFFF;
	while (*name != 0) {
		++len;

		/* TODO: support for unicode and case sensitivity */
		tmp8 = tolower(*name++);
		if (utf8_to_utf32(&tmp8, 1, &tmp32) < 0) /* Invalid unicode */
			return -EINVAL;

		hash = crc32c(hash, &tmp32, 4);
	}

	key->hash = ((hash & 0x3FFFFF) << 10) | (len & 0x3FF);
	return 0;
}
