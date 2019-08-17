// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/dir.c
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/slab.h>
#include <linux/buffer_head.h>
#include "apfs.h"
#include "btree.h"
#include "dir.h"
#include "inode.h"
#include "key.h"
#include "message.h"
#include "node.h"
#include "super.h"
#include "transaction.h"

/**
 * apfs_drec_from_query - Read the directory record found by a successful query
 * @query:	the query that found the record
 * @drec:	Return parameter.  The directory record found.
 *
 * Reads the directory record into @drec and performs some basic sanity checks
 * as a protection against crafted filesystems.  Returns 0 on success or
 * -EFSCORRUPTED otherwise.
 *
 * The caller must not free @query while @drec is in use, because @drec->name
 * points to data on disk.
 */
int apfs_drec_from_query(struct apfs_query *query, struct apfs_drec *drec)
{
	char *raw = query->node->object.bh->b_data;
	struct apfs_drec_hashed_key *de_key;
	struct apfs_drec_val *de;
	int namelen = query->key_len - sizeof(*de_key);

	if (namelen < 1)
		return -EFSCORRUPTED;
	if (query->len < sizeof(*de))
		return -EFSCORRUPTED;

	de = (struct apfs_drec_val *)(raw + query->off);
	de_key = (struct apfs_drec_hashed_key *)(raw + query->key_off);

	if (namelen != (le32_to_cpu(de_key->name_len_and_hash) &
			APFS_DREC_LEN_MASK))
		return -EFSCORRUPTED;

	/* Filename must be NULL-terminated */
	if (de_key->name[namelen - 1] != 0)
		return -EFSCORRUPTED;

	drec->name = de_key->name;
	drec->name_len = namelen - 1; /* Don't count the NULL termination */
	drec->ino = le64_to_cpu(de->file_id);

	drec->type = le16_to_cpu(de->flags) & APFS_DREC_TYPE_MASK;
	if (drec->type != DT_FIFO && drec->type & 1) /* Invalid file type */
		drec->type = DT_UNKNOWN;
	return 0;
}

/**
 * apfs_inode_by_name - Find the cnid for a given filename
 * @dir:	parent directory
 * @child:	filename
 * @ino:	on return, the inode number found
 *
 * Returns 0 and the inode number (which is the cnid of the file
 * record); otherwise, return the appropriate error code.
 */
int apfs_inode_by_name(struct inode *dir, const struct qstr *child, u64 *ino)
{
	struct super_block *sb = dir->i_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_key key;
	struct apfs_query *query;
	struct apfs_drec drec;
	u64 cnid = dir->i_ino;
	int err;

	down_read(&sbi->s_big_sem);

	apfs_init_drec_hashed_key(sb, cnid, child->name, &key);

	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query) {
		err = -ENOMEM;
		goto out;
	}
	query->key = &key;

	/*
	 * Distinct filenames in the same directory may (rarely) share the same
	 * hash.  The query code cannot handle that because their order in the
	 * b-tree would	depend on their unnormalized original names.  Just get
	 * all the candidates and check them one by one.
	 */
	query->flags |= APFS_QUERY_CAT | APFS_QUERY_ANY_NAME | APFS_QUERY_EXACT;
	do {
		err = apfs_btree_query(sb, &query);
		if (err)
			goto out;
		err = apfs_drec_from_query(query, &drec);
		if (err)
			goto out;
	} while (unlikely(apfs_filename_cmp(sb, child->name, drec.name)));

	*ino = drec.ino;
out:
	apfs_free_query(sb, query);
	up_read(&sbi->s_big_sem);
	return err;
}

static int apfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_key key;
	struct apfs_query *query;
	u64 cnid = inode->i_ino;
	loff_t pos;
	int err = 0;

	down_read(&sbi->s_big_sem);

	if (ctx->pos == 0) {
		if (!dir_emit_dot(file, ctx))
			goto out;
		ctx->pos++;
	}
	if (ctx->pos == 1) {
		if (!dir_emit_dotdot(file, ctx))
			goto out;
		ctx->pos++;
	}

	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query) {
		err = -ENOMEM;
		goto out;
	}

	/* We want all the children for the cnid, regardless of the name */
	apfs_init_drec_hashed_key(sb, cnid, NULL /* name */, &key);
	query->key = &key;
	query->flags = APFS_QUERY_CAT | APFS_QUERY_MULTIPLE | APFS_QUERY_EXACT;

	pos = ctx->pos - 2;
	while (1) {
		struct apfs_drec drec;
		/*
		 * We query for the matching records, one by one. After we
		 * pass ctx->pos we begin to emit them.
		 *
		 * TODO: Faster approach for large directories?
		 */

		err = apfs_btree_query(sb, &query);
		if (err == -ENODATA) { /* Got all the records */
			err = 0;
			break;
		}
		if (err)
			break;

		err = apfs_drec_from_query(query, &drec);
		if (err) {
			apfs_alert(sb, "bad dentry record in directory 0x%llx",
				   cnid);
			break;
		}

		err = 0;
		if (pos <= 0) {
			if (!dir_emit(ctx, drec.name, drec.name_len,
				      drec.ino, drec.type))
				break;
			ctx->pos++;
		}
		pos--;
	}

	if (pos < 0)
		ctx->pos -= pos;
	apfs_free_query(sb, query);

out:
	up_read(&sbi->s_big_sem);
	return err;
}

const struct file_operations apfs_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= apfs_readdir,
};

/**
 * apfs_build_dentry_key - Allocate and initialize the key for a dentry record
 * @dentry:	in-memory dentry to record
 * @hash:	filename hash
 * @key_p:	on return, a pointer to the new on-disk key structure
 *
 * Returns the length of the key, or a negative error code in case of failure.
 */
static int apfs_build_dentry_key(struct dentry *dentry, u64 hash,
				 struct apfs_drec_hashed_key **key_p)
{
	struct apfs_drec_hashed_key *key;
	struct qstr *qname = &dentry->d_name;
	u16 namelen = qname->len + 1; /* We count the null-termination */
	struct inode *parent = d_inode(dentry->d_parent);
	int key_len;

	key_len = sizeof(*key) + namelen;
	key = kmalloc(key_len, GFP_KERNEL);
	if (!key)
		return -ENOMEM;

	/* TODO: move this to a wrapper function in key.c */
	key->hdr.obj_id_and_type =
		cpu_to_le64(apfs_ino(parent) |
			    (u64)APFS_TYPE_DIR_REC << APFS_OBJ_TYPE_SHIFT);

	key->name_len_and_hash = cpu_to_le32(namelen | hash);
	strcpy(key->name, qname->name);

	*key_p = key;
	return key_len;
}

/**
 * apfs_build_dentry_val - Allocate and initialize the value for a dentry record
 * @dentry:	in-memory dentry to record
 * @inode:	vfs inode for the dentry
 * @sibling_id:	sibling id for this hardlink (0 for none)
 * @val_p:	on return, a pointer to the new on-disk value structure
 *
 * Returns the length of the value, or a negative error code in case of failure.
 */
static int apfs_build_dentry_val(struct dentry *dentry, struct inode *inode,
				 u64 sibling_id, struct apfs_drec_val **val_p)
{
	struct apfs_drec_val *val;
	struct apfs_xf_blob *xblob;
	struct apfs_x_field *xfield;
	struct timespec64 time = current_time(inode);
	int val_len;
	__le64 *raw_sibling_id;

	/* The dentry record may have one xfield: the sibling id */
	val_len = sizeof(*val);
	if (sibling_id)
		val_len += sizeof(*xblob) +
			   sizeof(*xfield) + sizeof(*raw_sibling_id);

	val = kmalloc(val_len, GFP_KERNEL);
	if (!val)
		return -ENOMEM;
	*val_p = val;

	val->file_id = cpu_to_le64(apfs_ino(inode));
	val->date_added = cpu_to_le64(time.tv_sec * NSEC_PER_SEC +
				      time.tv_nsec);
	val->flags = cpu_to_le16((inode->i_mode >> 12) & 15); /* File type */

	if (!sibling_id)
		return val_len;

	xblob = (struct apfs_xf_blob *)val->xfields;
	xblob->xf_num_exts = cpu_to_le16(1);
	xblob->xf_used_data = cpu_to_le16(sizeof(*raw_sibling_id));

	xfield = (struct apfs_x_field *)xblob->xf_data;
	xfield->x_type = APFS_DREC_EXT_TYPE_SIBLING_ID;
	xfield->x_flags = 0; /* TODO: proper flags here? */
	xfield->x_size = cpu_to_le16(sizeof(*raw_sibling_id));

	raw_sibling_id = (__le64 *)(xfield + 1);
	*raw_sibling_id = cpu_to_le64(sibling_id);
	return val_len;
}

/**
 * apfs_create_dentry_rec - Create a dentry record in the catalog b-tree
 * @dentry:	in-memory dentry to record
 * @inode:	vfs inode for the dentry
 * @sibling_id:	sibling id for this hardlink (0 for none)
 *
 * Returns 0 on success or a negative error code in case of failure.
 */
static int apfs_create_dentry_rec(struct dentry *dentry, struct inode *inode,
				  u64 sibling_id)
{
	struct super_block *sb = dentry->d_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct qstr *qname = &dentry->d_name;
	struct inode *parent = d_inode(dentry->d_parent);
	struct apfs_key key;
	struct apfs_query *query;
	struct apfs_drec_hashed_key *raw_key = NULL;
	struct apfs_drec_val *raw_val = NULL;
	int key_len, val_len;
	struct apfs_inode_val *parent_raw;
	struct timespec64 time = current_time(inode);
	int ret;

	apfs_init_drec_hashed_key(sb, apfs_ino(parent), qname->name, &key);
	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query)
		return -ENOMEM;
	query->key = &key;
	query->flags |= APFS_QUERY_CAT;

	ret = apfs_btree_query(sb, &query);
	if (ret && ret != -ENODATA)
		goto fail;

	key_len = apfs_build_dentry_key(dentry, key.number, &raw_key);
	if (key_len < 0) {
		ret = key_len;
		goto fail;
	}
	val_len = apfs_build_dentry_val(dentry, inode, sibling_id, &raw_val);
	if (val_len < 0) {
		ret = val_len;
		goto fail;
	}

	/* TODO: deal with hash collisions */
	ret = apfs_btree_insert(query, raw_key, key_len, raw_val, val_len);
	if (ret)
		goto fail;

	/* Now update the parent inode.  XXX: this should all be shared code */
	apfs_free_query(sb, query);

	apfs_init_inode_key(apfs_ino(parent), &key);
	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query)
		return -ENOMEM;
	query->key = &key;
	query->flags |= APFS_QUERY_CAT | APFS_QUERY_EXACT;

	ret = apfs_btree_query(sb, &query);
	if (ret)
		goto fail;

	/* XXX: only single-node trees are supported, so no need for cow here */
	parent_raw = (void *)query->node->object.bh->b_data + query->off;
	parent->i_mtime = parent->i_ctime = time;
	parent_raw->mod_time = parent_raw->change_time =
			cpu_to_le64(time.tv_sec * NSEC_PER_SEC + time.tv_nsec);
	le32_add_cpu(&parent_raw->nchildren, 1);

fail:
	kfree(raw_val);
	kfree(raw_key);
	apfs_free_query(sb, query);
	return ret;
}

/**
 * apfs_build_sibling_val - Allocate and initialize a sibling link's value
 * @dentry:	in-memory dentry for this hardlink
 * @val_p:	on return, a pointer to the new on-disk value structure
 *
 * Returns the length of the value, or a negative error code in case of failure.
 */
static int apfs_build_sibling_val(struct dentry *dentry,
				  struct apfs_sibling_val **val_p)
{
	struct apfs_sibling_val *val;
	struct qstr *qname = &dentry->d_name;
	u16 namelen = qname->len + 1; /* We count the null-termination */
	struct inode *parent = d_inode(dentry->d_parent);
	int val_len;

	val_len = sizeof(*val) + namelen;
	val = kmalloc(val_len, GFP_KERNEL);
	if (!val)
		return -ENOMEM;

	val->parent_id = cpu_to_le64(apfs_ino(parent));
	val->name_len = cpu_to_le16(namelen);
	strcpy(val->name, qname->name);

	*val_p = val;
	return val_len;
}

/**
 * apfs_create_sibling_link_rec - Create a sibling link record for a dentry
 * @dentry:	the in-memory dentry
 * @inode:	vfs inode for the dentry
 * @sibling_id:	sibling id for this hardlink
 *
 * Returns 0 on success or a negative error code in case of failure.
 */
static int apfs_create_sibling_link_rec(struct dentry *dentry,
					struct inode *inode, u64 sibling_id)
{
	struct super_block *sb = dentry->d_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_key key;
	struct apfs_query *query = NULL;
	struct apfs_sibling_link_key raw_key;
	struct apfs_sibling_val *raw_val;
	int val_len;
	int ret;

	apfs_init_sibling_link_key(apfs_ino(inode), sibling_id, &key);
	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query)
		return -ENOMEM;
	query->key = &key;
	query->flags |= APFS_QUERY_CAT;

	ret = apfs_btree_query(sb, &query);
	if (ret && ret != -ENODATA)
		goto fail;

	raw_key.hdr.obj_id_and_type =
		cpu_to_le64(apfs_ino(inode) |
			    (u64)APFS_TYPE_SIBLING_LINK << APFS_OBJ_TYPE_SHIFT);
	raw_key.sibling_id = cpu_to_le64(sibling_id);
	val_len = apfs_build_sibling_val(dentry, &raw_val);
	if (val_len < 0)
		goto fail;

	ret = apfs_btree_insert(query, &raw_key, sizeof(raw_key),
				raw_val, val_len);
	kfree(raw_val);

fail:
	apfs_free_query(sb, query);
	return ret;
}

/**
 * apfs_create_sibling_map_rec - Create a sibling map record for a dentry
 * @dentry:	the in-memory dentry
 * @inode:	vfs inode for the dentry
 * @sibling_id:	sibling id for this hardlink
 *
 * Returns 0 on success or a negative error code in case of failure.
 */
static int apfs_create_sibling_map_rec(struct dentry *dentry,
				       struct inode *inode, u64 sibling_id)
{
	struct super_block *sb = dentry->d_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_key key;
	struct apfs_query *query = NULL;
	struct apfs_sibling_map_key raw_key;
	struct apfs_sibling_map_val raw_val;
	int ret;

	apfs_init_sibling_map_key(sibling_id, &key);
	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query)
		return -ENOMEM;
	query->key = &key;
	query->flags |= APFS_QUERY_CAT;

	ret = apfs_btree_query(sb, &query);
	if (ret && ret != -ENODATA)
		goto fail;

	raw_key.hdr.obj_id_and_type =
		cpu_to_le64(sibling_id |
			    (u64)APFS_TYPE_SIBLING_MAP << APFS_OBJ_TYPE_SHIFT);
	raw_val.file_id = cpu_to_le64(apfs_ino(inode));

	ret = apfs_btree_insert(query, &raw_key, sizeof(raw_key),
				&raw_val, sizeof(raw_val));

fail:
	apfs_free_query(sb, query);
	return ret;
}

/**
 * apfs_create_sibling_recs - Create sibling link and map records for a dentry
 * @dentry:	the in-memory dentry
 * @inode:	vfs inode for the dentry
 * @sibling_id:	on return, the sibling id for this hardlink
 *
 * Returns 0 on success or a negative error code in case of failure.
 */
static int apfs_create_sibling_recs(struct dentry *dentry,
				    struct inode *inode, u64 *sibling_id)
{
	struct super_block *sb = dentry->d_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_superblock *vsb_raw = sbi->s_vsb_raw;
	u64 cnid;
	int ret;

	/* Sibling ids come from the same pool as the inode numbers */
	ASSERT(sbi->s_xid == le64_to_cpu(vsb_raw->apfs_o.o_xid));
	cnid = le64_to_cpu(vsb_raw->apfs_next_obj_id);
	le64_add_cpu(&vsb_raw->apfs_next_obj_id, 1);

	ret = apfs_create_sibling_link_rec(dentry, inode, cnid);
	if (ret)
		return ret;
	ret = apfs_create_sibling_map_rec(dentry, inode, cnid);
	if (ret)
		return ret;

	*sibling_id = cnid;
	return 0;
}

int apfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
	       dev_t rdev)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	u64 sibling_id = 0;
	int err;

	err = apfs_transaction_start(sb);
	if (err)
		return err;

	inode = apfs_new_inode(dir, mode, rdev);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_abort;
	}

	err = apfs_create_inode_rec(sb, inode, dentry);
	if (err)
		goto out_discard_inode;

	if (!S_ISDIR(mode)) {
		/* This isn't really mandatory for a single link... */
		err = apfs_create_sibling_recs(dentry, inode, &sibling_id);
		if (err)
			goto out_discard_inode;
	}
	err = apfs_create_dentry_rec(dentry, inode, sibling_id);
	if (err)
		goto out_discard_inode;

	err = apfs_transaction_commit(sb);
	if (err)
		goto out_discard_inode;

	d_instantiate_new(dentry, inode);
	return 0;

out_discard_inode:
	inode_dec_link_count(inode);
	discard_new_inode(inode);
out_abort:
	apfs_transaction_abort(sb);
	return err;
}

int apfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return apfs_mknod(dir, dentry, mode | S_IFDIR, 0 /* rdev */);
}

int apfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool excl)
{
	return apfs_mknod(dir, dentry, mode, 0 /* rdev */);
}

int apfs_link(struct dentry *old_dentry, struct inode *dir,
	      struct dentry *dentry)
{
	struct super_block *sb = dir->i_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct inode *inode = d_inode(old_dentry);
	struct apfs_inode_val *inode_raw;
	struct apfs_key key;
	struct apfs_query *query = NULL;
	struct timespec64 time = current_time(inode);
	u64 sibling_id = 0;
	int err;

	err = apfs_transaction_start(sb);
	if (err)
		return err;

	/* Update the inode's link count.  XXX: this should be shared code */
	apfs_init_inode_key(inode->i_ino, &key);
	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query) {
		err = -ENOMEM;
		goto out_abort;
	}
	query->key = &key;
	query->flags |= APFS_QUERY_CAT | APFS_QUERY_EXACT;

	err = apfs_btree_query(sb, &query);
	if (err)
		goto out_abort;

	/* XXX: only single-node trees are supported, so no need for cow here */
	inode_raw = (void *)query->node->object.bh->b_data + query->off;
	inode->i_ctime = time;
	inode_raw->change_time = cpu_to_le64(time.tv_sec * NSEC_PER_SEC +
					     time.tv_nsec);
	inode_inc_link_count(inode);
	le32_add_cpu(&inode_raw->nchildren, 1);
	ihold(inode);
	apfs_free_query(sb, query);
	query = NULL;

	/* TODO: create sibling records for primary link, if they don't exist */
	err = apfs_create_sibling_recs(dentry, inode, &sibling_id);
	if (err)
		goto out_iput;
	err = apfs_create_dentry_rec(dentry, inode, sibling_id);
	if (err)
		goto out_iput;

	err = apfs_transaction_commit(sb);
	if (err)
		goto out_iput;

	d_instantiate(dentry, inode);
	return 0;

out_iput:
	inode_dec_link_count(inode);
	iput(inode);
out_abort:
	apfs_free_query(sb, query);
	apfs_transaction_abort(sb);
	return err;
}
