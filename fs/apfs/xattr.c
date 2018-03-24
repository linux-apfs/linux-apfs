// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/xattr.c
 *
 * Copyright (C) 2018 Ernesto A. Fernandez <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/buffer_head.h>
#include <linux/xattr.h>
#include "apfs.h"
#include "key.h"

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
	struct apfs_key *key;
	struct apfs_query *query;
	char *xattr;
	u64 cnid = inode->i_ino;
	int ret;

	key = kmalloc(sizeof(*key), GFP_KERNEL);
	if (!key)
		return -ENOMEM;
	ret = apfs_init_key(APFS_RT_NAMED_ATTR, cnid, name, key);
	if (ret)
		goto fail;

	query = apfs_alloc_query(sbi->s_cat_tree->root, NULL /* parent */);
	if (!query) {
		ret = -ENOMEM;
		goto fail;
	}
	query->key = key;
	query->flags |= APFS_QUERY_CAT;

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
	struct apfs_key *key;
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
	apfs_init_key(APFS_RT_NAMED_ATTR, cnid, NULL /* name */, key);
	query->key = key;
	query->flags = APFS_QUERY_CAT | APFS_QUERY_MULTIPLE;

	while (1) {
		char *raw;
		int namelen;
		struct apfs_xattr_key *this_key;

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
		ret = -EFSCORRUPTED;
		raw = query->table->t_node.bh->b_data;
		namelen = query->key_len - sizeof(*this_key);
		if (namelen <= 0) /* xattr name must have at least one char */
			break;
		this_key = (struct apfs_xattr_key *)(raw + query->key_off);
		if (this_key->name[namelen - 1] != 0)
			break;

		/* TODO: don't list the xattrs with no handler */
		if (buffer) {
			if (namelen > free) {
				ret = -ERANGE;
				break;
			}
			memcpy(buffer, this_key->name, namelen);
			buffer += namelen;
		}
		free -= namelen;
	}
	apfs_free_query(sb, query);

cleanup:
	kfree(key);
	return ret;
}
