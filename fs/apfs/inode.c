// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/inode.c
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/slab.h>
#include <linux/buffer_head.h>
#include <linux/mpage.h>
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
	u32 rdev = 0;

	if (query->len < sizeof(*inode_val))
		goto corrupted;

	inode_val = (struct apfs_inode_val *)(raw + query->off);

	ai->i_parent_id = le64_to_cpu(inode_val->parent_id);
	ai->i_extent_id = le64_to_cpu(inode_val->private_id);
	inode->i_mode = le16_to_cpu(inode_val->mode);
	i_uid_write(inode, (uid_t)le32_to_cpu(inode_val->owner));
	i_gid_write(inode, (gid_t)le32_to_cpu(inode_val->group));

	if (!S_ISDIR(inode->i_mode)) {
		/*
		 * Directory inodes don't store their link count, so to provide
		 * it we would have to actually count the subdirectories. The
		 * HFS/HFS+ modules just leave it at 1, and so do we, for now.
		 */
		set_nlink(inode, le32_to_cpu(inode_val->nlink));
	} else {
		ai->i_nchildren = le32_to_cpu(inode_val->nchildren);
	}

	inode->i_atime = apfs_timespec(inode_val->access_time);
	inode->i_ctime = apfs_timespec(inode_val->change_time);
	inode->i_mtime = apfs_timespec(inode_val->mod_time);
	ai->i_crtime = apfs_timespec(inode_val->create_time);

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
 * Runs a catalog query for the apfs_ino(@inode) inode record; returns a pointer
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

/**
 * apfs_test_inode - Check if the inode matches a 64-bit inode number
 * @inode:	inode to test
 * @cnid:	pointer to the inode number
 */
static int apfs_test_inode(struct inode *inode, void *cnid)
{
	u64 *ino = cnid;

	return apfs_ino(inode) == *ino;
}

/**
 * apfs_set_inode - Set a 64-bit inode number on the given inode
 * @inode:	inode to set
 * @cnid:	pointer to the inode number
 */
static int apfs_set_inode(struct inode *inode, void *cnid)
{
	apfs_set_ino(inode, *(u64 *)cnid);
	return 0;
}

/**
 * apfs_iget_locked - Wrapper for iget5_locked()
 * @sb:		filesystem superblock
 * @cnid:	64-bit inode number
 *
 * Works the same as iget_locked(), but can handle 64-bit inode numbers on
 * 32-bit architectures.
 */
static struct inode *apfs_iget_locked(struct super_block *sb, u64 cnid)
{
	return iget5_locked(sb, cnid, apfs_test_inode, apfs_set_inode, &cnid);
}

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
 * apfs_build_inode_val - Allocate and initialize the value for an inode record
 * @inode:	vfs inode to record
 * @qname:	filename for primary link
 * @val_p:	on return, a pointer to the new on-disk value structure
 *
 * Returns the length of the value, or a negative error code in case of failure.
 */
static int apfs_build_inode_val(struct inode *inode, struct qstr *qname,
				struct apfs_inode_val **val_p)
{
	struct apfs_inode_val *val;
	struct apfs_xf_blob *xblob;
	struct apfs_x_field *xcurrent;
	char *xdata;
	int xfield_num, xfield_used_data;
	int namelen, padded_namelen;
	int val_len;
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

	val->parent_id = cpu_to_le64(APFS_I(inode)->i_parent_id);
	val->private_id = cpu_to_le64(apfs_ino(inode));

	val->mod_time = apfs_timestamp(inode->i_mtime);
	val->create_time = val->change_time = val->access_time = val->mod_time;

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

/*
 * apfs_inode_rename - Update the primary name reported in an inode record
 * @inode:	the in-memory inode
 * @new_name:	name of the new primary link (NULL if unchanged)
 * @query:	the query that found the inode record
 *
 * Returns 0 on success, or a negative error code in case of failure.
 */
static int apfs_inode_rename(struct inode *inode, char *new_name,
			     struct apfs_query *query)
{
	char *raw = query->node->object.bh->b_data;
	struct apfs_inode_key raw_key;
	struct apfs_inode_val *old_raw_inode, *new_raw_inode = NULL;
	struct qstr qname;
	int val_len;
	int err = 0;

	if (!new_name)
		return 0;

	apfs_key_set_hdr(APFS_TYPE_INODE, apfs_ino(inode), &raw_key);

	/*
	 * XXX: All xfields not created by this module will be dropped.  I
	 * really need a generic way to handle xfields...
	 */
	qname.name = new_name;
	qname.len = strlen(new_name);
	val_len = apfs_build_inode_val(inode, &qname, &new_raw_inode);
	if (val_len < 0) {
		err = val_len;
		goto fail;
	}
	old_raw_inode = (struct apfs_inode_val *)(raw + query->off);
	memcpy(new_raw_inode, old_raw_inode, sizeof(*old_raw_inode));

	/* Just remove the old record and create a new one */
	err = apfs_btree_remove(query);
	if (err)
		goto fail;
	err = apfs_btree_insert(query, &raw_key, sizeof(raw_key),
				new_raw_inode, val_len);

fail:
	kfree(new_raw_inode);
	return err;
}

/**
 * apfs_update_inode - Update an existing inode record
 * @inode:	the modified in-memory inode
 * @new_name:	name of the new primary link (NULL if unchanged)
 *
 * Returns 0 on success, or a negative error code in case of failure.
 */
int apfs_update_inode(struct inode *inode, char *new_name)
{
	struct super_block *sb = inode->i_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_inode_info *ai = APFS_I(inode);
	struct apfs_query *query;
	struct apfs_btree_node_phys *node_raw;
	struct apfs_inode_val *inode_raw;
	int err;

	query = apfs_inode_lookup(inode);
	if (IS_ERR(query))
		return PTR_ERR(query);

	err = apfs_inode_rename(inode, new_name, query);
	if (err)
		goto fail;

	/* XXX: only single-node trees are supported, so no need for cow here */
	node_raw = (void *)query->node->object.bh->b_data;
	ASSERT(sbi->s_xid == le64_to_cpu(node_raw->btn_o.o_xid));
	inode_raw = (void *)node_raw + query->off;

	inode_raw->parent_id = cpu_to_le64(ai->i_parent_id);
	inode_raw->owner = cpu_to_le32(i_uid_read(inode));
	inode_raw->group = cpu_to_le32(i_gid_read(inode));
	inode_raw->mode = cpu_to_le16(inode->i_mode);

	inode_raw->access_time = apfs_timestamp(inode->i_atime);
	inode_raw->change_time = apfs_timestamp(inode->i_ctime);
	inode_raw->mod_time = apfs_timestamp(inode->i_mtime);
	inode_raw->create_time = apfs_timestamp(ai->i_crtime);

	if (S_ISDIR(inode->i_mode)) {
		inode_raw->nchildren = cpu_to_le32(ai->i_nchildren);
	} else {
		/* Orphaned inodes are still linked under private-dir */
		inode_raw->nlink = cpu_to_le32(inode->i_nlink ? : 1);
	}

	/* TODO: set size and block count */

fail:
	apfs_free_query(sb, query);
	return err;
}

/**
 * apfs_delete_inode - Delete an inode record and update the volume file count
 * @inode: the vfs inode to delete
 *
 * Returns 0 on success or a negative error code in case of failure.
 */
static int apfs_delete_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_superblock *vsb_raw = sbi->s_vsb_raw;
	struct apfs_query *query;
	int ret;

	query = apfs_inode_lookup(inode);
	if (IS_ERR(query))
		return PTR_ERR(query);
	ret = apfs_btree_remove(query);
	apfs_free_query(sb, query);

	ASSERT(sbi->s_xid == le64_to_cpu(vsb_raw->apfs_o.o_xid));
	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		le64_add_cpu(&vsb_raw->apfs_num_files, -1);
		break;
	case S_IFDIR:
		le64_add_cpu(&vsb_raw->apfs_num_directories, -1);
		break;
	case S_IFLNK:
		le64_add_cpu(&vsb_raw->apfs_num_symlinks, -1);
		break;
	default:
		le64_add_cpu(&vsb_raw->apfs_num_other_fsobjects, -1);
		break;
	}
	return ret;
}

void apfs_evict_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;

	if (is_bad_inode(inode) || inode->i_nlink)
		goto out_clear;

	if (apfs_transaction_start(sb))
		goto out_report;
	if (apfs_delete_inode(inode))
		goto out_abort;
	if (apfs_delete_orphan_link(inode))
		goto out_abort;
	if (apfs_transaction_commit(sb))
		goto out_abort;
	goto out_clear;

out_abort:
	apfs_transaction_abort(sb);
out_report:
	apfs_warn(sb,
		  "failed to delete orphan inode 0x%llx\n", apfs_ino(inode));
out_clear:
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
}

/**
 * apfs_insert_inode_locked - Wrapper for insert_inode_locked4()
 * @inode: vfs inode to insert in cache
 *
 * Works the same as insert_inode_locked(), but can handle 64-bit inode numbers
 * on 32-bit architectures.
 */
static int apfs_insert_inode_locked(struct inode *inode)
{
	u64 cnid = apfs_ino(inode);

	return insert_inode_locked4(inode, cnid, apfs_test_inode, &cnid);
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
	apfs_set_ino(inode, cnid);
	inode_init_owner(inode, dir, mode); /* TODO: handle override */
	ai->i_parent_id = apfs_ino(dir);
	set_nlink(inode, 1);
	ai->i_nchildren = 0;

	ai->i_crtime = current_time(inode);
	inode->i_atime = inode->i_mtime = inode->i_ctime = ai->i_crtime;
	vsb_raw->apfs_last_mod_time = apfs_timestamp(ai->i_crtime);

	/* Symlinks are not yet supported */
	ASSERT(!S_ISLNK(mode));
	if (S_ISREG(mode))
		le64_add_cpu(&vsb_raw->apfs_num_files, 1);
	else if (S_ISDIR(mode))
		le64_add_cpu(&vsb_raw->apfs_num_directories, 1);
	else
		le64_add_cpu(&vsb_raw->apfs_num_other_fsobjects, 1);

	if (apfs_insert_inode_locked(inode)) {
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

	apfs_key_set_hdr(APFS_TYPE_INODE, apfs_ino(inode), &raw_key);

	val_len = apfs_build_inode_val(inode, &dentry->d_name, &raw_val);
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
