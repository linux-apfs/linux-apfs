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
#include "key.h"

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

	query = apfs_alloc_query(sbi->s_cat_tree->root, NULL /* parent */);
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
		ret = -EFSCORRUPTED;
		goto done;
	}
	raw = query->table->t_node.bh->b_data;
	ext = (struct apfs_cat_extent *)(raw + query->off);
	ext_key = (struct apfs_extent_key *)(raw + query->key_off);

	/* Find the block offset of iblock within the extent */
	blk_off = iblock - (le64_to_cpu(ext_key->off) >> inode->i_blkbits);

	/* Find the block number of iblock within the disk */
	bno = le64_to_cpu(ext->block) + blk_off;
	map_bh(bh_result, sb, bno);

	length = le64_to_cpu(ext->length) - (blk_off << inode->i_blkbits);
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
 * @tail:	on success points to the record tail, or NULL if it's not there
 *
 * Returns a pointer to the data, or NULL in case of failure. TODO: use more
 * descriptive error pointers.
 *
 * On success, the caller must release @table after using the data, unless it's
 * the root table of the catalog.
 */
static struct apfs_cat_inode *apfs_get_inode(struct super_block *sb, u64 cnid,
					     struct apfs_table **table,
					     struct apfs_cat_inode_tail **tail)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_key *key;
	struct apfs_cat_inode *raw;
	int len;

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

	if (sizeof(*raw) > len) {
		/*
		 * Sanity check: prevent out of bounds read of d_len and the
		 * other raw inode fields. I don't yet know how to safely read
		 * the filename, because four bytes sometimes show up before
		 * it that would mess with the length.
		 */
		goto fail;
	}
	*tail = NULL;
	if (sizeof(*raw) + le16_to_cpu(raw->d_len) + sizeof(**tail) <= len) {
		/*
		 * A tail fits in this inode record. The extra bytes around
		 * the filename are too few to make a difference.
		 */
		*tail = (struct apfs_cat_inode_tail *)
				((char *)raw + len - sizeof(**tail));
	}

	return raw;

fail:
	if (*table != sbi->s_cat_tree->root)
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
	struct apfs_cat_inode *raw_inode;
	struct apfs_cat_inode_tail *raw_itail;
	struct apfs_table *table;
	unsigned long ino = cnid;
	u64 secs;

	if (ino < cnid) {
		apfs_msg(sb, KERN_WARNING, "inode number overflow");
		return ERR_PTR(-EOVERFLOW);
	}
	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;
	ai = APFS_I(inode);

	raw_inode = apfs_get_inode(sb, (u64)ino, &table, &raw_itail);
	if (!raw_inode) {
		err = ERR_PTR(-EIO);
		goto failed_get;
	}

	inode->i_mode = le16_to_cpu(raw_inode->d_mode);
	/* Allow the user to override the ownership */
	if (sbi->s_flags & APFS_UID_OVERRIDE)
		inode->i_uid = sbi->s_uid;
	else
		i_uid_write(inode, (uid_t)le32_to_cpu(raw_inode->d_owner));
	if (sbi->s_flags & APFS_GID_OVERRIDE)
		inode->i_gid = sbi->s_gid;
	else
		i_gid_write(inode, (gid_t)le32_to_cpu(raw_inode->d_group));

	if (S_ISREG(inode->i_mode) || S_ISLNK(inode->i_mode)) {
		/*
		 * It seems that hard links are only allowed for regular files,
		 * and perhaps for symlinks.
		 *
		 * Directory inodes don't store their link count, so to provide
		 * it we would have to actually count the subdirectories. The
		 * HFS/HFS+ modules just leave it at 1, and so do we, for now.
		 */
		set_nlink(inode, le64_to_cpu(raw_inode->d_link_count));
		if (inode->i_nlink < le64_to_cpu(raw_inode->d_link_count)) {
			apfs_msg(sb, KERN_WARNING, "hardlink count overflow");
			err = ERR_PTR(-EOVERFLOW);
			goto failed_read;
		}
	}
	if (raw_itail) {
		inode->i_size = le64_to_cpu(raw_itail->d_size);
		inode->i_blocks = le64_to_cpu(raw_itail->d_phys_size)
							>> inode->i_blkbits;
	} else {
		/* Assume empty for now, but the real size must be elsewhere. */
		inode->i_size = inode->i_blocks = 0;
	}

	/* APFS stores the time as unsigned nanoseconds since the epoch */
	secs = le64_to_cpu(raw_inode->d_atime);
	inode->i_atime.tv_nsec = do_div(secs, NSEC_PER_SEC);
	inode->i_atime.tv_sec = secs;
	secs = le64_to_cpu(raw_inode->d_ctime);
	inode->i_ctime.tv_nsec = do_div(secs, NSEC_PER_SEC);
	inode->i_ctime.tv_sec = secs;
	secs = le64_to_cpu(raw_inode->d_mtime);
	inode->i_mtime.tv_nsec = do_div(secs, NSEC_PER_SEC);
	inode->i_mtime.tv_sec = secs;
	ai->i_crtime = le64_to_cpu(raw_inode->d_crtime); /* Not used for now */

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

	if (table != sbi->s_cat_tree->root) /* Never release the root table */
		apfs_release_table(table);
	/* Inode flags are not important for now, leave them at 0 */
	unlock_new_inode(inode);
	return inode;

failed_read:
	if (table != sbi->s_cat_tree->root)
		apfs_release_table(table);
failed_get:
	iget_failed(inode);
	return err;
}
