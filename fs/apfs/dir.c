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
#include "key.h"
#include "message.h"
#include "super.h"
#include "table.h"

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
	struct apfs_key *key;
	u64 cnid = dir->i_ino;
	int err;

	key = kmalloc(sizeof(*key), GFP_KERNEL);
	if (!key)
		return -ENOMEM;

	/* We are looking for a key record */
	apfs_init_key(APFS_TYPE_DIR_REC, cnid, child->name,
		      child->len, 0 /* offset */, key);

	err = apfs_cat_resolve(dir->i_sb, key, ino);

	kfree(key);
	return err;
}

static int apfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_key *key;
	struct apfs_query *query;
	u64 cnid = inode->i_ino;
	loff_t pos;
	int err = 0;

	if (ctx->pos == 0) {
		if (!dir_emit_dot(file, ctx))
			return 0;
		ctx->pos++;
	}
	if (ctx->pos == 1) {
		if (!dir_emit_dotdot(file, ctx))
			return 0;
		ctx->pos++;
	}

	key = kmalloc(sizeof(*key), GFP_KERNEL);
	if (!key)
		return -ENOMEM;
	query = apfs_alloc_query(sbi->s_cat_root, NULL /* parent */);
	if (!query) {
		err = -ENOMEM;
		goto cleanup;
	}

	/* We want all the children for the cnid, regardless of the name */
	apfs_init_key(APFS_TYPE_DIR_REC, cnid, NULL /* name */,
		      0 /* namelen */, 0 /* offset */, key);
	query->key = key;
	query->flags = APFS_QUERY_CAT | APFS_QUERY_MULTIPLE | APFS_QUERY_EXACT;

	pos = ctx->pos - 2;
	while (1) {
		/*
		 * We query for the matching records, one by one. After we
		 * pass ctx->pos we begin to emit them.
		 *
		 * TODO: Faster approach for large directories?
		 */
		char *raw;
		int namelen;
		struct apfs_drec_hashed_key *de_key;
		struct apfs_drec_val *de;

		err = apfs_btree_query(sb, &query);
		if (err == -ENODATA) { /* Got all the records */
			err = 0;
			break;
		}
		if (err)
			break;

		raw = query->table->t_node.bh->b_data;
		de = (struct apfs_drec_val *)(raw + query->off);
		de_key = (struct apfs_drec_hashed_key *)(raw + query->key_off);
		namelen = query->key_len - sizeof(*de_key);

		/*
		 * Check that the found key and data are long enough to fit
		 * the structures we expect, and that the filename is
		 * NULL-terminated. Otherwise the filesystem is invalid.
		 */
		err = -EFSCORRUPTED;
		if (namelen < 1 || de_key->name[namelen - 1] != 0) {
			apfs_alert(sb, "bad dentry key in directory 0x%llx",
				   cnid);
			break;
		}
		if (query->len < sizeof(*de)) {
			apfs_alert(sb, "bad dentry data in directory 0x%llx",
				   cnid);
			break;
		}

		err = 0;
		if (pos <= 0) {
			/* TODO: what if the dentry flags are corrupted? */
			if (!dir_emit(ctx, de_key->name,
				      namelen - 1, /* Don't count NULL */
				      le64_to_cpu(de->file_id),
				      le16_to_cpu(de->flags)
					      & APFS_DREC_TYPE_MASK))
				break;
			ctx->pos++;
		}
		pos--;
	}

	if (pos < 0)
		ctx->pos -= pos;
	apfs_free_query(sb, query);

cleanup:
	kfree(key);
	return err;
}

const struct file_operations apfs_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= apfs_readdir,
};
