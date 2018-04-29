// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/inode.c
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/slab.h>
#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <asm/div64.h>
#include "apfs.h"
#include "btree.h"
#include "dir.h"
#include "inode.h"
#include "key.h"
#include "message.h"
#include "super.h"
#include "table.h"
#include "xattr.h"

static int apfs_get_block(struct inode *inode, sector_t iblock,
			  struct buffer_head *bh_result, int create)
{
	struct super_block *sb = inode->i_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_key *key;
	struct apfs_query *query;
	struct apfs_cat_extent *ext;
	struct apfs_extent_key *ext_key;
	char *raw;
	u64 blk_off, bno, length;
	int ret = 0;

	key = kmalloc(sizeof(*key), GFP_KERNEL);
	if (!key)
		return -ENOMEM;
	/* We will search for the extent that covers iblock */
	apfs_init_key(APFS_RT_EXTENT, inode->i_ino, NULL /* name */,
		      0 /* namelen */, iblock << inode->i_blkbits, key);

	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query) {
		ret = -ENOMEM;
		goto fail;
	}
	query->key = key;
	query->flags = APFS_QUERY_CAT;

	ret = apfs_btree_query(sb, &query);
	if (ret)
		goto done;

	if (query->len != sizeof(*ext) || query->key_len != sizeof(*ext_key)) {
		apfs_alert(sb, "bad extent record for inode 0x%llx",
			   (unsigned long long) inode->i_ino);
		ret = -EFSCORRUPTED;
		goto done;
	}
	raw = query->table->t_node.bh->b_data;
	ext = (struct apfs_cat_extent *)(raw + query->off);
	ext_key = (struct apfs_extent_key *)(raw + query->key_off);

	/* Find the block offset of iblock within the extent */
	blk_off = iblock - (le64_to_cpu(ext_key->off) >> inode->i_blkbits);

	/* Extents representing holes have block number 0 */
	if (ext->block != 0) {
		/* Find the block number of iblock within the disk */
		bno = le64_to_cpu(ext->block) + blk_off;
		map_bh(bh_result, sb, bno);
	}

	length = le64_to_cpu(ext->length) - (blk_off << inode->i_blkbits);
	/* I think b_size needs to be a multiple of the block size */
	length = round_up(length, sb->s_blocksize);
	if (length > bh_result->b_size) /* Don't map more than requested */
		length = bh_result->b_size;

	bh_result->b_size = length;

done:
	apfs_free_query(sb, query);
fail:
	kfree(key);
	return ret;
}

static int apfs_readpage(struct file *file, struct page *page)
{
	return mpage_readpage(page, apfs_get_block);
}

static int apfs_readpages(struct file *file, struct address_space *mapping,
			  struct list_head *pages, unsigned int nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, apfs_get_block);
}

static sector_t apfs_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping, block, apfs_get_block);
}

const struct address_space_operations apfs_aops = {
	.readpage	= apfs_readpage,
	.readpages	= apfs_readpages,
	.bmap		= apfs_bmap,
};

/**
 * apfs_get_inode - Get the raw metadata corresponding to an inode number
 * @sb:		filesystem superblock
 * @cnid:	the inode number
 * @table:	on success it will point to the table that stores the data
 * @isize:	on success points to the inode size attr. NULL if there is none
 *
 * Returns a pointer to the data, or NULL in case of failure. TODO: use more
 * descriptive error pointers.
 *
 * On success, the caller must release @table after using the data, unless it's
 * the root table of the catalog.
 */
static struct apfs_inode *apfs_get_inode(struct super_block *sb, u64 cnid,
					 struct apfs_table **table,
					 struct apfs_inode_size **isize)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_key *key;
	struct apfs_inode *raw;
	int len, rest;
	int i;

	key = kmalloc(sizeof(*key), GFP_KERNEL);
	if (!key)
		return NULL;
	/* Looking for an inode record, so this is the only field of the key */
	apfs_init_key(APFS_RT_INODE, cnid, NULL /* name */, 0 /* namelen */,
		      0 /* offset */, key);

	raw = apfs_cat_get_data(sb, key, &len, table);
	kfree(key);
	if (!raw)
		return NULL;

	/* Now we must parse the optional attrs to find the one for the size */
	*isize = NULL;
	if (sizeof(*raw) > len) {
		/*
		 * Sanity check: prevent out of bounds read of i_attr_count
		 * and the other raw inode fields.
		 */
		goto fail;
	}
	rest = len - sizeof(*raw);
	rest -= le16_to_cpu(raw->i_attr_count) * sizeof(raw->i_opt_attrs[0]);
	if (rest < 0)
		goto fail;
	for (i = 0; i < le16_to_cpu(raw->i_attr_count); ++i) {
		int attrlen;
		int attrtype;

		/* Attribute length is padded to a multiple of 8 */
		attrlen = round_up(le16_to_cpu(raw->i_opt_attrs[i].ia_len), 8);
		if (attrlen > rest)
			break;
		attrtype = le16_to_cpu(raw->i_opt_attrs[i].ia_type);
		if (attrtype == APFS_INODE_SIZE) {
			/* The only optional attr we care about, for now */
			*isize = (struct apfs_inode_size *)((char *)raw +
							    len - rest);
			break;
		}
		rest -= attrlen;
	}

	return raw;

fail:
	if (*table != sbi->s_cat_root)
		apfs_release_table(*table);
	return NULL;
}

/**
 * apfs_iget - Populate inode structures with metadata from disk
 * @sb:		filesystem superblock
 * @cnid:	inode number
 *
 * Populates the vfs inode and the corresponding apfs_inode_info structure.
 * Returns a pointer to the vfs inode in case of success, or an appropriate
 * error pointer otherwise.
 *
 * Most fields of the on-disk inode are 64 bits long and they may not fit in
 * the vfs fields. In that case this function will throw an overflow error.
 *
 * TODO: other filesystems also support 64 bit inode numbers; check out how
 * they handle this. And perhaps make some of this code architecture-dependent.
 */
struct inode *apfs_iget(struct super_block *sb, u64 cnid)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct inode *inode, *err;
	struct apfs_inode_info *ai;
	struct apfs_inode *raw_inode;
	struct apfs_inode_size *raw_isize;
	struct apfs_table *table;
	unsigned long ino = cnid;
	u64 secs;

	if (ino < cnid) {
		apfs_warn(sb, "inode number overflow: 0x%llx", cnid);
		return ERR_PTR(-EOVERFLOW);
	}
	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;
	ai = APFS_I(inode);

	raw_inode = apfs_get_inode(sb, (u64)ino, &table, &raw_isize);
	if (!raw_inode) {
		err = ERR_PTR(-EIO);
		goto failed_get;
	}

	inode->i_mode = le16_to_cpu(raw_inode->i_mode);
	/* Allow the user to override the ownership */
	if (sbi->s_flags & APFS_UID_OVERRIDE)
		inode->i_uid = sbi->s_uid;
	else
		i_uid_write(inode, (uid_t)le32_to_cpu(raw_inode->i_owner));
	if (sbi->s_flags & APFS_GID_OVERRIDE)
		inode->i_gid = sbi->s_gid;
	else
		i_gid_write(inode, (gid_t)le32_to_cpu(raw_inode->i_group));

	if (S_ISREG(inode->i_mode) || S_ISLNK(inode->i_mode)) {
		/*
		 * It seems that hard links are only allowed for regular files,
		 * and perhaps for symlinks.
		 *
		 * Directory inodes don't store their link count, so to provide
		 * it we would have to actually count the subdirectories. The
		 * HFS/HFS+ modules just leave it at 1, and so do we, for now.
		 */
		set_nlink(inode, le64_to_cpu(raw_inode->i_link_count));
		if (inode->i_nlink < le64_to_cpu(raw_inode->i_link_count)) {
			apfs_warn(sb, "hardlink count overflow in inode 0x%llx",
				  cnid);
			err = ERR_PTR(-EOVERFLOW);
			goto failed_read;
		}
	}
	if (raw_isize) {
		inode->i_size = le64_to_cpu(raw_isize->i_size);
		inode->i_blocks = le64_to_cpu(raw_isize->i_phys_size)
							>> inode->i_blkbits;
	} else {
		/*
		 * This inode is "empty", but it may actually hold compressed
		 * data in the named attribute com.apple.decmpfs, and sometimes
		 * in com.apple.ResourceFork
		 */
		inode->i_size = inode->i_blocks = 0;
	}

	/* APFS stores the time as unsigned nanoseconds since the epoch */
	secs = le64_to_cpu(raw_inode->i_atime);
	inode->i_atime.tv_nsec = do_div(secs, NSEC_PER_SEC);
	inode->i_atime.tv_sec = secs;
	secs = le64_to_cpu(raw_inode->i_ctime);
	inode->i_ctime.tv_nsec = do_div(secs, NSEC_PER_SEC);
	inode->i_ctime.tv_sec = secs;
	secs = le64_to_cpu(raw_inode->i_mtime);
	inode->i_mtime.tv_nsec = do_div(secs, NSEC_PER_SEC);
	inode->i_mtime.tv_sec = secs;
	secs = le64_to_cpu(raw_inode->i_crtime);
	ai->i_crtime.tv_nsec = do_div(secs, NSEC_PER_SEC);
	ai->i_crtime.tv_sec = secs;

	/* A lot of operations still missing, of course */
	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &apfs_file_inode_operations;
		inode->i_fop = &apfs_file_operations;
		inode->i_mapping->a_ops = &apfs_aops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &apfs_dir_inode_operations;
		inode->i_fop = &apfs_dir_operations;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &apfs_symlink_inode_operations;
	} else {
		inode->i_op = &apfs_special_inode_operations;
	}

	if (table != sbi->s_cat_root) /* Never release the root table */
		apfs_release_table(table);
	/* Inode flags are not important for now, leave them at 0 */
	unlock_new_inode(inode);
	return inode;

failed_read:
	if (table != sbi->s_cat_root)
		apfs_release_table(table);
failed_get:
	iget_failed(inode);
	return err;
}

int apfs_getattr(const struct path *path, struct kstat *stat,
		 u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct apfs_inode_info *ai = APFS_I(inode);

	stat->result_mask |= STATX_BTIME;
	stat->btime.tv_sec = ai->i_crtime.tv_sec;
	stat->btime.tv_nsec = ai->i_crtime.tv_nsec;

	if (apfs_xattr_get(inode, "com.apple.decmpfs", NULL, 0) >= 0)
		stat->attributes |= STATX_ATTR_COMPRESSED;

	stat->attributes_mask |= STATX_ATTR_COMPRESSED;

	generic_fillattr(inode, stat);
	return 0;
}
