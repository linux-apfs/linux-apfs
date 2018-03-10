// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/xattr.c
 *
 * Copyright (C) 2018 Ernesto A. Fernandez <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/buffer_head.h>
#include <linux/xattr.h>
#include "apfs.h"

/**
 * apfs_xattr_get - Find and read a named attribute
 * @inode:	inode the attribute belongs to
 * @name:	name of the attribute
 * @buffer:	where to copy the attribute data
 * @size:	size of @buffer
 *
 * Finds an extended attribute and copies its value to @buffer, if provided. If
 * @buffer is NULL, just computes the size of the buffer required.
 *
 * Returns the number of bytes used/required, or a negative error code in case
 * of failure.
 */
int apfs_xattr_get(struct inode *inode, const char *name, void *buffer,
		   size_t size)
{
	struct super_block *sb = inode->i_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_cat_key *key;
	struct apfs_query *query;
	char *xattr;
	int name_len;
	u64 cnid = inode->i_ino;
	int ret = 0;

	name_len = strlen(name) + 2; /* One mystery byte and terminating null */

	key = kmalloc(sizeof(*key) + name_len, GFP_KERNEL);
	if (!key)
		return -ENOMEM;
	key->k_cnid = cpu_to_le64(cnid | ((u64)APFS_RT_NAMED_ATTR << 56));
	key->k_len = name_len;
	strcpy(key->k_name + 1, name); /* TODO: could this just be a pointer? */

	query = apfs_alloc_query(sbi->s_cat_tree->root, NULL /* parent */);
	if (!query) {
		ret = -ENOMEM;
		goto fail;
	}
	query->key = key;
	query->cmp = apfs_cat_keycmp;

	ret = apfs_btree_query(sb, &query);
	if (ret)
		goto fail;

	ret = query->len; /* Return the length of the xattr */
	if (!buffer) {
		/* All we want is the length */
		goto done;
	}
	if (ret > size) {
		/* xattr won't fit in the buffer */
		ret = -ERANGE;
		goto done;
	}

	xattr = query->table->t_node.bh->b_data + query->off;
	memcpy(buffer, xattr, ret);

done:
	apfs_free_query(sb, query);
fail:
	kfree(key);
	return ret;
}

static int apfs_xattr_apple_get(const struct xattr_handler *handler,
				struct dentry *unused, struct inode *inode,
				const char *name, void *buffer, size_t size)
{
	name = xattr_full_name(handler, name);
	return apfs_xattr_get(inode, name, buffer, size);
}

static const struct xattr_handler apfs_xattr_apple_handler = {
	.prefix	= "com.apple.",
	.get	= apfs_xattr_apple_get,
};

const struct xattr_handler *apfs_xattr_handlers[] = {
	&apfs_xattr_apple_handler,
	NULL
};

ssize_t apfs_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct inode *inode = d_inode(dentry);
	struct super_block *sb = inode->i_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_cat_key *key;
	struct apfs_query *query;
	u64 cnid = inode->i_ino;
	size_t free = size;
	ssize_t ret;

	key = kmalloc(sizeof(*key), GFP_KERNEL);
	if (!key)
		return -ENOMEM;
	query = apfs_alloc_query(sbi->s_cat_tree->root, NULL /* parent */);
	if (!query) {
		ret = -ENOMEM;
		goto cleanup;
	}

	/* We want all the xattrs for the cnid, regardless of the name */
	key->k_cnid = cpu_to_le64(cnid | ((u64)APFS_RT_NAMED_ATTR << 56));
	query->key = key;
	query->cmp = apfs_cat_anon_keycmp;
	query->flags = APFS_QUERY_MULTIPLE;

	while (1) {
		char *raw;
		struct apfs_cat_key *key;

		ret = apfs_btree_query(sb, &query);
		if (ret == -ENODATA) { /* Got all the xattrs */
			ret = size - free;
			break;
		}
		if (ret)
			break;

		/*
		 * Check that the found key is long enough to fit the structures
		 * we expect, and that the attribute name is NULL-terminated.
		 * Otherwise the filesystem is invalid.
		 */
		ret = -EINVAL;
		raw = query->table->t_node.bh->b_data;
		if (query->key_len < sizeof(*key))
			break;
		key = (struct apfs_cat_key *)(raw + query->key_off);
		if (query->key_len != sizeof(*key) + key->k_len + 1 ||
		    key->k_len == 0 || key->k_name[key->k_len] != 0)
			break;

		/* TODO: don't list the xattrs with no handler */
		if (buffer) {
			if (key->k_len > free) {
				ret = -ERANGE;
				break;
			}
			memcpy(buffer, key->k_name + 1, key->k_len);
			buffer += key->k_len;
		}
		free -= key->k_len;
	}
	apfs_free_query(sb, query);

cleanup:
	kfree(key);
	return ret;
}
