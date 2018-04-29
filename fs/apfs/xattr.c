// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/xattr.c
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/buffer_head.h>
#include <linux/xattr.h>
#include "apfs.h"
#include "btree.h"
#include "key.h"
#include "super.h"
#include "table.h"
#include "message.h"
#include "xattr.h"

/**
 * apfs_xattr_extents_read - Read the value of a xattr from its extents
 * @parent:	inode the attribute belongs to
 * @xattr:	the xattr data in the catalog tree
 * @buffer:	where to copy the attribute value
 * @size:	size of @buffer
 *
 * Copies the value of @xattr to @buffer, if provided. If @buffer is NULL, just
 * computes the size of the buffer required.
 *
 * Returns the number of bytes used/required, or a negative error code in case
 * of failure.
 */
static int apfs_xattr_extents_read(struct inode *parent,
				   struct apfs_xattr_ext *xattr,
				   void *buffer, size_t size)
{
	struct super_block *sb = parent->i_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_key *key = NULL;
	struct apfs_query *query;
	int length;
	int ret;
	int i;

	if (le16_to_cpu(xattr->header.len) + sizeof(xattr->header) !=
							sizeof(*xattr)) {
		apfs_alert(sb, "bad extent-based xattr record for inode 0x%llx",
			   (unsigned long long) parent->i_ino);
		return -EFSCORRUPTED;
	}

	length = le64_to_cpu(xattr->size);
	if (length < 0 || length < le64_to_cpu(xattr->size))
		return -EOVERFLOW;

	if (!buffer) /* All we want is the length */
		return length;
	if (length > size) /* xattr won't fit in the buffer */
		return -ERANGE;

	key = kmalloc(sizeof(*key), GFP_KERNEL);
	if (!key)
		return -ENOMEM;
	/* We will read all the extents, starting with the last one */
	apfs_init_key(APFS_RT_EXTENT, xattr->cnid, NULL /* name */,
		      0 /* namelen */, length, key);

	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query) {
		ret = -ENOMEM;
		goto fail;
	}
	query->key = key;
	query->flags = APFS_QUERY_CAT | APFS_QUERY_MULTIPLE;

	/*
	 * The logic in this loop would allow a crafted filesystem with a large
	 * number of redundant extents to become stuck for a long time. We use
	 * the xattr length to put a limit on the number of iterations.
	 */
	ret = -EFSCORRUPTED;
	for (i = 0; i < (length >> parent->i_blkbits) + 2; i++) {
		struct apfs_cat_extent *ext;
		struct apfs_extent_key *ext_key;
		char *raw;
		u64 block, block_count, file_off;
		int err;
		int j;

		err = apfs_btree_query(sb, &query);
		if (err == -ENODATA) { /* No more records to search */
			ret = length;
			goto done;
		}
		if (err) {
			ret = err;
			goto done;
		}
		if (query->curr->type != APFS_RT_EXTENT) {
			/*
			 * Non-exact multiple query means we will get a record
			 * of the wrong type after finding all the extents.
			 */
			ret = length;
			goto done;
		}

		if (query->len != sizeof(*ext) ||
		    query->key_len != sizeof(*ext_key)) {
			apfs_alert(sb, "bad extent for xattr in inode 0x%llx",
				   (unsigned long long) parent->i_ino);
			ret = -EFSCORRUPTED;
			goto done;
		}
		raw = query->table->t_node.bh->b_data;
		ext = (struct apfs_cat_extent *)(raw + query->off);
		ext_key = (struct apfs_extent_key *)(raw + query->key_off);

		block = le64_to_cpu(ext->block);
		block_count = (le64_to_cpu(ext->length) + sb->s_blocksize) >>
			      sb->s_blocksize_bits;
		file_off = le64_to_cpu(ext_key->off);
		for (j = 0; j < block_count; ++j) {
			struct buffer_head *bh;
			int bytes;

			if (length <= file_off) /* Read the whole extent */
				break;
			bytes = min(sb->s_blocksize,
				    (unsigned long)(length - file_off));

			bh = sb_bread(sb, block + j);
			if (!bh) {
				ret = -EIO;
				goto done;
			}
			memcpy(buffer + file_off, bh->b_data, bytes);
			brelse(bh);
			block++;
			file_off = file_off + bytes;
		}
	}

done:
	apfs_free_query(sb, query);
fail:
	kfree(key);
	return ret;
}

/**
 * apfs_xattr_inline_read - Read the value of an inline xattr
 * @parent:	inode the attribute belongs to
 * @xattr:	the xattr data in the catalog tree
 * @buffer:	where to copy the attribute value
 * @size:	size of @buffer
 *
 * Copies the inline value of @xattr to @buffer, if provided. If @buffer is
 * NULL, just computes the size of the buffer required.
 *
 * Returns the number of bytes used/required, or a negative error code in case
 * of failure.
 */
static int apfs_xattr_inline_read(struct inode *parent,
				  struct apfs_xattr_inline *xattr,
				  void *buffer, size_t size)
{
	int length = le16_to_cpu(xattr->header.len);

	if (!buffer) /* All we want is the length */
		return length;
	if (length > size) /* xattr won't fit in the buffer */
		return -ERANGE;
	memcpy(buffer, xattr->value, length);
	return length;
}

/**
 * apfs_xattr_get - Find and read a named attribute
 * @inode:	inode the attribute belongs to
 * @name:	name of the attribute
 * @buffer:	where to copy the attribute value
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
	struct apfs_xattr_header *header;
	char *raw;
	u64 cnid = inode->i_ino;
	int ret;

	key = kmalloc(sizeof(*key), GFP_KERNEL);
	if (!key)
		return -ENOMEM;
	ret = apfs_init_key(APFS_RT_NAMED_ATTR, cnid, name, 0 /* namelen */,
			    0 /* offset */, key);
	if (ret)
		goto fail;

	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query) {
		ret = -ENOMEM;
		goto fail;
	}
	query->key = key;
	query->flags |= APFS_QUERY_CAT | APFS_QUERY_EXACT;

	ret = apfs_btree_query(sb, &query);
	if (ret)
		goto done;

	raw = query->table->t_node.bh->b_data;
	header = (struct apfs_xattr_header *)(raw + query->off);
	if (query->len < sizeof(*header) ||
	    sizeof(*header) + le16_to_cpu(header->len) != query->len) {
		apfs_alert(sb, "bad xattr record in inode 0x%llx", cnid);
		ret = -EFSCORRUPTED;
		goto done;
	}

	if (le16_to_cpu(header->flags) & APFS_XATTR_HAS_EXTENTS)
		ret = apfs_xattr_extents_read(inode,
					      (struct apfs_xattr_ext *)header,
					      buffer, size);
	else
		ret = apfs_xattr_inline_read(inode,
					     (struct apfs_xattr_inline *)header,
					     buffer, size);

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
	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query) {
		ret = -ENOMEM;
		goto cleanup;
	}

	/* We want all the xattrs for the cnid, regardless of the name */
	apfs_init_key(APFS_RT_NAMED_ATTR, cnid, NULL /* name */,
		      0 /* namelen */, 0 /* offset */, key);
	query->key = key;
	query->flags = APFS_QUERY_CAT | APFS_QUERY_MULTIPLE | APFS_QUERY_EXACT;

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

		raw = query->table->t_node.bh->b_data;
		this_key = (struct apfs_xattr_key *)(raw + query->key_off);
		namelen = query->key_len - sizeof(*this_key);

		/*
		 * Check that the found key is long enough to fit the structure
		 * we expect, and that the attribute name is NULL-terminated.
		 * Otherwise the filesystem is invalid.
		 */
		if (namelen < 1 || this_key->name[namelen - 1] != 0) {
			apfs_alert(sb, "bad xattr key in inode %llx", cnid);
			ret = -EFSCORRUPTED;
			break;
		}

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
