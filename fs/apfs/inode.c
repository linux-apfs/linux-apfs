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
#include "extents.h"
#include "inode.h"
#include "key.h"
#include "message.h"
#include "node.h"
#include "super.h"
#include "xattr.h"

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

static const struct address_space_operations apfs_aops = {
	.readpage	= apfs_readpage,
	.readpages	= apfs_readpages,
	.bmap		= apfs_bmap,
};

/**
 * apfs_inode_set_ops - Set up an inode's operations
 * @inode:	vfs inode to set up
 * @rdev:	device id (0 if not a device file)
 *
 * For device files, also sets the device id to @rdev.
 */
static void apfs_inode_set_ops(struct inode *inode, dev_t rdev)
{
	/* A lot of operations still missing, of course */
	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &apfs_file_inode_operations;
		inode->i_fop = &apfs_file_operations;
		inode->i_mapping->a_ops = &apfs_aops;
		break;
	case S_IFDIR:
		inode->i_op = &apfs_dir_inode_operations;
		inode->i_fop = &apfs_dir_operations;
		break;
	case S_IFLNK:
		inode->i_op = &apfs_symlink_inode_operations;
		break;
	default:
		inode->i_op = &apfs_special_inode_operations;
		init_special_inode(inode, inode->i_mode, rdev);
		break;
	}
}

/**
 * apfs_inode_from_query - Read the inode found by a successful query
 * @query:	the query that found the record
 * @inode:	vfs inode to be filled with the read data
 *
 * Reads the inode record into @inode and performs some basic sanity checks,
 * mostly as a protection against crafted filesystems.  Returns 0 on success
 * or a negative error code otherwise.
 */
static int apfs_inode_from_query(struct apfs_query *query, struct inode *inode)
{
	struct apfs_inode_info *ai = APFS_I(inode);
	struct apfs_inode_val *inode_val;
	struct apfs_dstream *dstream = NULL;
	struct apfs_xf_blob *xblob;
	struct apfs_x_field *xfield;
	char *raw = query->node->object.bh->b_data;
	int rest, i;
	u64 secs;
	u32 rdev = 0;

	if (query->len < sizeof(*inode_val))
		goto corrupted;

	inode_val = (struct apfs_inode_val *)(raw + query->off);

	ai->i_extent_id = le64_to_cpu(inode_val->private_id);
	inode->i_mode = le16_to_cpu(inode_val->mode);
	i_uid_write(inode, (uid_t)le32_to_cpu(inode_val->owner));
	i_gid_write(inode, (gid_t)le32_to_cpu(inode_val->group));

	if (S_ISREG(inode->i_mode) || S_ISLNK(inode->i_mode)) {
		/*
		 * It seems that hard links are only allowed for regular files,
		 * and perhaps for symlinks.
		 *
		 * Directory inodes don't store their link count, so to provide
		 * it we would have to actually count the subdirectories. The
		 * HFS/HFS+ modules just leave it at 1, and so do we, for now.
		 */
		set_nlink(inode, le32_to_cpu(inode_val->nlink));
	}

	/* APFS stores the time as unsigned nanoseconds since the epoch */
	secs = le64_to_cpu(inode_val->access_time);
	inode->i_atime.tv_nsec = do_div(secs, NSEC_PER_SEC);
	inode->i_atime.tv_sec = secs;
	secs = le64_to_cpu(inode_val->change_time);
	inode->i_ctime.tv_nsec = do_div(secs, NSEC_PER_SEC);
	inode->i_ctime.tv_sec = secs;
	secs = le64_to_cpu(inode_val->mod_time);
	inode->i_mtime.tv_nsec = do_div(secs, NSEC_PER_SEC);
	inode->i_mtime.tv_sec = secs;
	secs = le64_to_cpu(inode_val->create_time);
	ai->i_crtime.tv_nsec = do_div(secs, NSEC_PER_SEC);
	ai->i_crtime.tv_sec = secs;

	xblob = (struct apfs_xf_blob *) inode_val->xfields;
	xfield = (struct apfs_x_field *) xblob->xf_data;
	rest = query->len - (sizeof(*inode_val) + sizeof(*xblob));
	rest -= le16_to_cpu(xblob->xf_num_exts) * sizeof(xfield[0]);
	if (rest < 0)
		goto corrupted;
	for (i = 0; i < le16_to_cpu(xblob->xf_num_exts); ++i) {
		int attrlen;

		/* Attribute length is padded to a multiple of 8 */
		attrlen = round_up(le16_to_cpu(xfield[i].x_size), 8);
		if (attrlen > rest)
			break;

		/* These are the only xfields we care about, for now */
		if (xfield[i].x_type == APFS_INO_EXT_TYPE_DSTREAM) {
			dstream = (struct apfs_dstream *)
					((char *)inode_val + query->len - rest);
			break;
		}
		if (xfield[i].x_type == APFS_INO_EXT_TYPE_RDEV) {
			__le32 *rdev_p = (void *)inode_val + query->len - rest;

			rdev = le32_to_cpu(*rdev_p);
		}

		rest -= attrlen;
	}

	if (dstream) {
		inode->i_size = le64_to_cpu(dstream->size);
		inode->i_blocks = le64_to_cpu(dstream->alloced_size) >> 9;
	} else {
		/*
		 * This inode is "empty", but it may actually hold compressed
		 * data in the named attribute com.apple.decmpfs, and sometimes
		 * in com.apple.ResourceFork
		 */
		inode->i_size = inode->i_blocks = 0;
	}

	apfs_inode_set_ops(inode, rdev);
	return 0;

corrupted:
	apfs_alert(inode->i_sb,
		   "bad inode record for inode 0x%llx", apfs_ino(inode));
	return -EFSCORRUPTED;
}

/**
 * apfs_inode_lookup - Lookup an inode record in the catalog b-tree
 * @inode:	vfs inode to lookup
 *
 * Runs a catalog query for the @inode->i_ino inode record; returns a pointer
 * to the query structure on success, or an error pointer in case of failure.
 */
static struct apfs_query *apfs_inode_lookup(const struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_key key;
	struct apfs_query *query;
	int ret;

	apfs_init_inode_key(apfs_ino(inode), &key);

	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query)
		return ERR_PTR(-ENOMEM);
	query->key = &key;
	query->flags |= APFS_QUERY_CAT | APFS_QUERY_EXACT;

	ret = apfs_btree_query(sb, &query);
	if (!ret)
		return query;

	apfs_free_query(sb, query);
	return ERR_PTR(ret);
}

#if BITS_PER_LONG == 64
#define apfs_iget_locked iget_locked
#else /* 64-bit inode numbers may not fit in the vfs inode */

/**
 * apfs_test_inode - Check if the inode matches a 64-bit inode number
 * @inode:	inode to test
 * @cnid:	pointer to the inode number
 */
static int apfs_test_inode(struct inode *inode, void *cnid)
{
	struct apfs_inode_info *ai = APFS_I(inode);
	u64 *ino = cnid;

	return ai->i_ino == *ino;
}

/**
 * apfs_set_inode - Set a 64-bit inode number on the given inode
 * @inode:	inode to set
 * @cnid:	pointer to the inode number
 */
static int apfs_set_inode(struct inode *inode, void *cnid)
{
	struct apfs_inode_info *ai = APFS_I(inode);
	u64 *ino = cnid;

	ai->i_ino = *ino;
	inode->i_ino = *ino; /* Just discard the higher bits here... */
	return 0;
}

/**
 * apfs_iget_locked - Wrapper for iget5_locked()
 * @sb:		filesystem superblock
 * @cnid:	64-bit inode number
 *
 * Works the same as iget_locked(), but supports 64-bit inode numbers.
 */
static struct inode *apfs_iget_locked(struct super_block *sb, u64 cnid)
{
	return iget5_locked(sb, cnid, apfs_test_inode, apfs_set_inode, &cnid);
}

#endif /* BITS_PER_LONG == 64 */

/**
 * apfs_iget - Populate inode structures with metadata from disk
 * @sb:		filesystem superblock
 * @cnid:	inode number
 *
 * Populates the vfs inode and the corresponding apfs_inode_info structure.
 * Returns a pointer to the vfs inode in case of success, or an appropriate
 * error pointer otherwise.
 */
struct inode *apfs_iget(struct super_block *sb, u64 cnid)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct inode *inode;
	struct apfs_query *query;
	int err;

	inode = apfs_iget_locked(sb, cnid);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	down_read(&sbi->s_big_sem);
	query = apfs_inode_lookup(inode);
	if (IS_ERR(query)) {
		err = PTR_ERR(query);
		goto fail;
	}
	err = apfs_inode_from_query(query, inode);
	apfs_free_query(sb, query);
	if (err)
		goto fail;
	up_read(&sbi->s_big_sem);

	/* Allow the user to override the ownership */
	if (sbi->s_flags & APFS_UID_OVERRIDE)
		inode->i_uid = sbi->s_uid;
	if (sbi->s_flags & APFS_GID_OVERRIDE)
		inode->i_gid = sbi->s_gid;

	/* Inode flags are not important for now, leave them at 0 */
	unlock_new_inode(inode);
	return inode;

fail:
	up_read(&sbi->s_big_sem);
	iget_failed(inode);
	return ERR_PTR(err);
}

int apfs_getattr(const struct path *path, struct kstat *stat,
		 u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct apfs_inode_info *ai = APFS_I(inode);

	stat->result_mask |= STATX_BTIME;
	stat->btime = ai->i_crtime;

	if (apfs_xattr_get(inode, APFS_XATTR_NAME_COMPRESSED, NULL, 0) >= 0)
		stat->attributes |= STATX_ATTR_COMPRESSED;

	stat->attributes_mask |= STATX_ATTR_COMPRESSED;

	generic_fillattr(inode, stat);
	stat->ino = apfs_ino(inode);
	return 0;
}

/**
 * apfs_new_inode - Create a new in-memory inode
 * @dir:	parent inode
 * @mode:	mode bits for the new inode
 * @rdev:	device id (0 if not a device file)
 *
 * Returns a pointer to the new vfs inode on success, or an error pointer in
 * case of failure.
 */
struct inode *apfs_new_inode(struct inode *dir, umode_t mode, dev_t rdev)
{
	struct super_block *sb = dir->i_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_superblock *vsb_raw = sbi->s_vsb_raw;
	struct inode *inode;
	struct apfs_inode_info *ai;
	u64 cnid;

	/* Updating on-disk structures here is odd, but it works for now */
	ASSERT(sbi->s_xid == le64_to_cpu(vsb_raw->apfs_o.o_xid));

	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	ai = APFS_I(inode);

	cnid = le64_to_cpu(vsb_raw->apfs_next_obj_id);
	le64_add_cpu(&vsb_raw->apfs_next_obj_id, 1);
	inode->i_ino = cnid;
#if BITS_PER_LONG == 32
	ai->ino = cnid;
#endif
	inode_init_owner(inode, dir, mode); /* TODO: handle override */
	set_nlink(inode, 1);

	ai->i_crtime = current_time(inode);
	inode->i_atime = inode->i_mtime = inode->i_ctime = ai->i_crtime;
	vsb_raw->apfs_last_mod_time = cpu_to_le64(
		     ai->i_crtime.tv_sec * NSEC_PER_SEC + ai->i_crtime.tv_nsec);

	/* Symlinks are not yet supported */
	ASSERT(!S_ISLNK(mode));
	if (S_ISREG(mode))
		le64_add_cpu(&vsb_raw->apfs_num_files, 1);
	else if (S_ISDIR(mode))
		le64_add_cpu(&vsb_raw->apfs_num_directories, 1);
	else
		le64_add_cpu(&vsb_raw->apfs_num_other_fsobjects, 1);

	/* TODO: use insert_inode_locked4() on 32-bit architectures */
	if (insert_inode_locked(inode)) {
		/* The inode number should have been free, but wasn't */
		make_bad_inode(inode);
		iput(inode);
		return ERR_PTR(-EFSCORRUPTED);
	}

	/* No need to dirty the inode, we'll write it to disk right away */
	apfs_inode_set_ops(inode, rdev);
	return inode;
}

/**
 * apfs_build_inode_val - Allocate and initialize the value for an inode record
 * @inode:	vfs inode to record
 * @dentry:	dentry for primary link
 * @val_p:	on return, a pointer to the new on-disk value structure
 *
 * Returns the length of the value, or a negative error code in case of failure.
 */
static int apfs_build_inode_val(struct inode *inode, struct dentry *dentry,
				struct apfs_inode_val **val_p)
{
	struct apfs_inode_val *val;
	struct inode *parent = d_inode(dentry->d_parent);
	struct apfs_xf_blob *xblob;
	struct apfs_x_field *xcurrent;
	char *xdata;
	int xfield_num, xfield_used_data;
	struct qstr *qname = &dentry->d_name;
	int namelen, padded_namelen;
	int val_len;
	struct timespec64 time;
	u64 timestamp;
	__le32 *rdev;

	val_len = sizeof(*val) + sizeof(*xblob);

	/* The name is stored in an xfield, padded with zeroes */
	namelen = qname->len + 1; /* We count the null-termination */
	padded_namelen = round_up(namelen, 8);
	val_len += sizeof(struct apfs_x_field) + padded_namelen;
	xfield_used_data = padded_namelen;
	xfield_num = 1;

	/* Device files have another xfield for the id */
	if (inode->i_rdev) {
		/* TODO: is this xfield actually padded? */
		val_len += sizeof(struct apfs_x_field) +
			   round_up(sizeof(*rdev), 8);
		xfield_used_data += round_up(sizeof(*rdev), 8);
		++xfield_num;
	}

	val = kzalloc(val_len, GFP_KERNEL);
	if (!val)
		return -ENOMEM;

	val->parent_id = cpu_to_le64(parent->i_ino);
	val->private_id = cpu_to_le64(inode->i_ino);

	/* APFS stores the time as unsigned nanoseconds since the epoch */
	time = inode->i_mtime;
	timestamp = time.tv_sec * NSEC_PER_SEC + time.tv_nsec;
	val->create_time = val->mod_time = val->change_time =
			   val->access_time = cpu_to_le64(timestamp);

	if (S_ISDIR(inode->i_mode))
		val->nchildren = 0;
	else
		val->nlink = cpu_to_le32(1);

	val->owner = cpu_to_le32(i_uid_read(inode));
	val->group = cpu_to_le32(i_gid_read(inode));
	val->mode = cpu_to_le16(inode->i_mode);

	xblob = (struct apfs_xf_blob *)val->xfields;
	xblob->xf_num_exts = cpu_to_le16(xfield_num);
	/* The official reference seems to be wrong here */
	xblob->xf_used_data = cpu_to_le16(xfield_used_data);

	/* Set the metadata for the name xfield */
	xcurrent = (struct apfs_x_field *)xblob->xf_data;
	xcurrent->x_type = APFS_INO_EXT_TYPE_NAME;
	xcurrent->x_flags = APFS_XF_DO_NOT_COPY;
	xcurrent->x_size = cpu_to_le16(namelen);

	if (inode->i_rdev) {
		/* Set the metadata for the device id xfield */
		++xcurrent;
		xcurrent->x_type = APFS_INO_EXT_TYPE_RDEV;
		xcurrent->x_flags = 0; /* TODO: proper flags here? */
		xcurrent->x_size = cpu_to_le16(sizeof(*rdev));
	}

	/* Now comes the xfield data, in the same order */
	xdata = (char *)(xcurrent + 1);
	strcpy(xdata, qname->name);
	xdata += padded_namelen;
	if (inode->i_rdev) {
		rdev = (__le32 *)xdata;
		*rdev = cpu_to_le32(inode->i_rdev);
		xdata += round_up(sizeof(*rdev), 8);
	}
	ASSERT(xdata - (char *)val == val_len);

	*val_p = val;
	return val_len;
}

/**
 * apfs_create_inode_rec - Create an inode record in the catalog b-tree
 * @sb:		filesystem superblock
 * @inode:	vfs inode to record
 * @dentry:	dentry for primary link
 *
 * Returns 0 on success or a negative error code in case of failure.
 */
int apfs_create_inode_rec(struct super_block *sb, struct inode *inode,
			  struct dentry *dentry)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_key key;
	struct apfs_query *query;
	struct apfs_inode_key raw_key;
	struct apfs_inode_val *raw_val;
	int val_len;
	int ret;

	apfs_init_inode_key(apfs_ino(inode), &key);
	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query)
		return -ENOMEM;
	query->key = &key;
	query->flags |= APFS_QUERY_CAT;

	ret = apfs_btree_query(sb, &query);
	if (ret && ret != -ENODATA)
		goto fail;

	/* TODO: move this to a wrapper function in key.c */
	raw_key.hdr.obj_id_and_type =
		cpu_to_le64(apfs_ino(inode) |
			    (u64)APFS_TYPE_INODE << APFS_OBJ_TYPE_SHIFT);

	val_len = apfs_build_inode_val(inode, dentry, &raw_val);
	if (val_len < 0) {
		ret = val_len;
		goto fail;
	}

	ret = apfs_btree_insert(query, &raw_key, sizeof(raw_key),
				raw_val, val_len);
	kfree(raw_val);

fail:
	apfs_free_query(sb, query);
	return ret;
}
