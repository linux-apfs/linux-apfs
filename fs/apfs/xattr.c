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
#include "extents.h"
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
				   struct apfs_xattr_val *xattr,
				   void *buffer, size_t size)
{
	struct super_block *sb = parent->i_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_key *key = NULL;
	struct apfs_query *query;
	struct apfs_xattr_dstream *xdata;
	int length;
	int ret;
	int i;

	xdata = (struct apfs_xattr_dstream *) xattr->xdata;
	length = le64_to_cpu(xdata->dstream.size);
	if (length < 0 || length < le64_to_cpu(xdata->dstream.size)) {
		apfs_warn(sb, "too large xattr in inode 0x%llx",
			  (unsigned long long) parent->i_ino);
		return -EOVERFLOW;
	}

	if (!buffer) /* All we want is the length */
		return length;
	if (length > size) /* xattr won't fit in the buffer */
		return -ERANGE;

	key = kmalloc(sizeof(*key), GFP_KERNEL);
	if (!key)
		return -ENOMEM;
	/* We will read all the extents, starting with the last one */
	apfs_init_key(sb, APFS_TYPE_FILE_EXTENT, xdata->xattr_obj_id,
		      NULL /* name */, 0 /* namelen */, length, key);

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
		struct apfs_file_extent ext;
		u64 block_count, file_off;
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
		if (query->curr->type != APFS_TYPE_FILE_EXTENT) {
			/*
			 * Non-exact multiple query means we will get a record
			 * of the wrong type after finding all the extents.
			 */
			ret = length;
			goto done;
		}

		err = apfs_extent_from_query(query, &ext);
		if (err) {
			apfs_alert(sb, "bad extent for xattr in inode 0x%llx",
				   (unsigned long long) parent->i_ino);
			ret = err;
			goto done;
		}

		block_count = ext.len >> sb->s_blocksize_bits;
		file_off = ext.logical_addr;
		for (j = 0; j < block_count; ++j) {
			struct buffer_head *bh;
			int bytes;

			if (length <= file_off) /* Read the whole extent */
				break;
			bytes = min(sb->s_blocksize,
				    (unsigned long)(length - file_off));

			bh = sb_bread(sb, ext.phys_block_num + j);
			if (!bh) {
				ret = -EIO;
				goto done;
			}
			memcpy(buffer + file_off, bh->b_data, bytes);
			brelse(bh);
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
				  struct apfs_xattr_val *xattr,
				  void *buffer, size_t size)
{
	int length = le16_to_cpu(xattr->xdata_len);

	if (!buffer) /* All we want is the length */
		return length;
	if (length > size) /* xattr won't fit in the buffer */
		return -ERANGE;
	memcpy(buffer, xattr->xdata, length);
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
	struct apfs_xattr_val *xattr;
	char *raw;
	u64 cnid = inode->i_ino;
	int xdata_len;
	int ret;

	key = kmalloc(sizeof(*key), GFP_KERNEL);
	if (!key)
		return -ENOMEM;
	apfs_init_key(sb, APFS_TYPE_XATTR, cnid, name, 0 /* namelen */,
		      0 /* offset */, key);

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
	xattr = (struct apfs_xattr_val *)(raw + query->off);

	if (query->len < sizeof(*xattr))
		goto corrupted;
	xdata_len = query->len - sizeof(*xattr);

	if (le16_to_cpu(xattr->flags) & APFS_XATTR_DATA_STREAM) {
		if (xdata_len != sizeof(struct apfs_xattr_dstream))
			goto corrupted;
		ret = apfs_xattr_extents_read(inode, xattr, buffer, size);
	} else {
		if (xdata_len != le16_to_cpu(xattr->xdata_len))
			goto corrupted;
		ret = apfs_xattr_inline_read(inode, xattr, buffer, size);
	}
	goto done;

corrupted:
	ret = -EFSCORRUPTED;
	apfs_alert(sb, "bad xattr record in inode 0x%llx", cnid);
done:
	apfs_free_query(sb, query);
fail:
	kfree(key);
	return ret;
}

static int apfs_xattr_osx_get(const struct xattr_handler *handler,
				struct dentry *unused, struct inode *inode,
				const char *name, void *buffer, size_t size)
{
	/* Ignore the fake 'osx' prefix */
	return apfs_xattr_get(inode, name, buffer, size);
}

static const struct xattr_handler apfs_xattr_osx_handler = {
	.prefix	= XATTR_MAC_OSX_PREFIX,
	.get	= apfs_xattr_osx_get,
};

/* On-disk xattrs have no namespace; use a fake 'osx' prefix in the kernel */
const struct xattr_handler *apfs_xattr_handlers[] = {
	&apfs_xattr_osx_handler,
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
	apfs_init_key(sb, APFS_TYPE_XATTR, cnid, NULL /* name */,
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

		if (buffer) {
			/* Prepend the fake 'osx' prefix before listing */
			if (namelen + XATTR_MAC_OSX_PREFIX_LEN > free) {
				ret = -ERANGE;
				break;
			}
			memcpy(buffer, XATTR_MAC_OSX_PREFIX,
			       XATTR_MAC_OSX_PREFIX_LEN);
			buffer += XATTR_MAC_OSX_PREFIX_LEN;
			memcpy(buffer, this_key->name, namelen);
			buffer += namelen;
		}
		free -= namelen + XATTR_MAC_OSX_PREFIX_LEN;
	}
	apfs_free_query(sb, query);

cleanup:
	kfree(key);
	return ret;
}
