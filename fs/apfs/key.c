// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/key.c
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/crc32c.h>
#include "apfs.h"
#include "key.h"
#include "unicode.h"

/**
 * apfs_cat_type - Read the record type of a catalog key
 * @key: the raw catalog key
 *
 * The record type is stored in the last byte of the cnid field; this function
 * returns that value.
 */
static inline int apfs_cat_type(struct apfs_key_header *key)
{
	return (le64_to_cpu(key->obj_id_and_type) & APFS_OBJ_TYPE_MASK)
			>> APFS_OBJ_TYPE_SHIFT;
}

/**
 * apfs_cat_cnid - Read the cnid value on a catalog key
 * @key: the raw catalog key
 *
 * The cnid value shares the its field with the record type. This function
 * masks that part away and returns the result.
 */
static inline u64 apfs_cat_cnid(struct apfs_key_header *key)
{
	return le64_to_cpu(key->obj_id_and_type) & APFS_OBJ_ID_MASK;
}

/**
 * apfs_filename_cmp - Normalize and compare two APFS filenames
 * @name1, @name2:	names to compare
 *
 * returns   0 if @name1 and @name2 are equal
 *	   < 0 if @name1 comes before @name2 in the btree
 *	   > 0 if @name1 comes after @name2 in the btree
 *
 * TODO: support case sensitive filesystems.
 */
int apfs_filename_cmp(const char *name1, const char *name2)
{
	struct apfs_unicursor cursor1, cursor2;

	apfs_init_unicursor(&cursor1, name1);
	apfs_init_unicursor(&cursor2, name2);

	while (1) {
		unicode_t uni1, uni2;

		uni1 = apfs_normalize_next(&cursor1);
		uni2 = apfs_normalize_next(&cursor2);

		if (uni1 != uni2)
			return uni1 < uni2 ? -1 : 1;
		if (!uni1)
			return 0;
	}
}

/**
 * apfs_keycmp - Compare two keys
 * @k1, @k2:	keys to compare
 *
 * returns   0 if @k1 and @k2 are equal
 *	   < 0 if @k1 comes before @k2 in the btree
 *	   > 0 if @k1 comes after @k2 in the btree
 */
int apfs_keycmp(struct apfs_key *k1, struct apfs_key *k2)
{
	if (k1->id != k2->id)
		return k1->id < k2->id ? -1 : 1;
	if (k1->type != k2->type)
		return k1->type < k2->type ? -1 : 1;
	if (k1->offset != k2->offset)
		return k1->offset < k2->offset ? -1 : 1;
	if (k2->name == NULL) /* We ignore the names (if they exist) */
		return 0;
	if (k1->hash != k2->hash)
		return k1->hash < k2->hash ? -1 : 1;

	if (k1->type == APFS_TYPE_XATTR) {
		/* xattr names seem to be always case sensitive */
		return strcmp(k1->name, k2->name);
	}

	/* Only guessing, I've never seen two names with the same hash. TODO */
	return apfs_filename_cmp(k1->name, k2->name);
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
	if (size < sizeof(struct apfs_key_header))
		return -EFSCORRUPTED;
	key->type = apfs_cat_type((struct apfs_key_header *)raw);
	key->id = apfs_cat_cnid((struct apfs_key_header *)raw);

	switch (key->type) {
	case APFS_TYPE_DIR_REC:
		if (size < sizeof(struct apfs_dentry_key) + 1 ||
		    *((char *)raw + size - 1) != 0) {
			/* Filename must have NULL-termination */
			return -EFSCORRUPTED;
		}
		key->hash = le32_to_cpu(((struct apfs_dentry_key *)raw)->hash);
		key->name = ((struct apfs_dentry_key *)raw)->name;
		key->offset = 0;
		break;
	case APFS_TYPE_XATTR:
		if (size < sizeof(struct apfs_xattr_key) + 1 ||
		    *((char *)raw + size - 1) != 0) {
			/* xattr name must have NULL-termination */
			return -EFSCORRUPTED;
		}
		key->hash = 0;
		key->name = ((struct apfs_xattr_key *)raw)->name;
		key->offset = 0;
		break;
	case APFS_TYPE_FILE_EXTENT:
		if (size != sizeof(struct apfs_file_extent_key))
			return -EFSCORRUPTED;
		key->hash = 0;
		key->name = NULL;
		key->offset = le64_to_cpu(
			((struct apfs_file_extent_key *)raw)->logical_addr);
		break;
	default:
		key->hash = 0;
		key->name = NULL;
		key->offset = 0;
		break;
	}

	return 0;
}

/**
 * apfs_read_omap_key - Parse an on-disk object map key
 * @raw:	pointer to the raw key
 * @size:	size of the raw key
 * @key:	apfs_key structure to store the result
 *
 * Returns 0 on success, or a negative error code otherwise.
 */
int apfs_read_omap_key(void *raw, int size, struct apfs_key *key)
{
	if (size < sizeof(struct apfs_omap_key))
		return -EFSCORRUPTED;

	key->type = 0;
	key->id = le64_to_cpu(((struct apfs_omap_key *)raw)->ok_oid);
	key->name = NULL;
	key->hash = 0;
	key->offset = 0;

	return 0;
}

/**
 * apfs_init_key - Initialize an in-memory key
 * @type:	type of the record
 * @id:		id for the record
 * @name:	name of the record (may be NULL)
 * @namelen:	for dentry keys, length of @name (without the NULL); otherwise 0
 * @offset:	for extent records, offset within the file; otherwise 0
 * @key:	apfs_key structure to initialize
 *
 * On success, @key will be ready to query for the record.
 */
void apfs_init_key(int type, u64 id, const char *name, int namelen,
		   u64 offset, struct apfs_key *key)
{
	struct apfs_unicursor cursor;
	u32 hash;

	key->type = type;
	key->id = id;
	key->name = name;
	key->offset = offset;
	if (name == NULL || type == APFS_TYPE_XATTR) {
		key->hash = 0;
		return;
	}

	/* TODO: support case sensitive filesystems */
	apfs_init_unicursor(&cursor, name);
	hash = 0xFFFFFFFF;

	while (1) {
		unicode_t utf32;

		utf32 = apfs_normalize_next(&cursor);
		if (!utf32)
			break;

		hash = crc32c(hash, &utf32, sizeof(utf32));
	}

	/* APFS counts the NULL termination for the filename length */
	key->hash = ((hash & 0x3FFFFF) << 10) | ((namelen + 1) & 0x3FF);
}
