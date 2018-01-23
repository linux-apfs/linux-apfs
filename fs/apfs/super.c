// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/super.c
 *
 * Copyright (C) 2018 Ernesto A. Fernandez <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/buffer_head.h>
#include "apfs.h"

void apfs_msg(struct super_block *sb, const char *prefix, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	printk("%sAPFS: %pV\n", prefix, &vaf);

	va_end(args);
}

static void apfs_put_super(struct super_block *sb)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);

	sb->s_fs_info = NULL;
	brelse(sbi->s_mnode.bh);
	brelse(sbi->s_vnode.bh);
	kfree(sbi);
}

static const struct super_operations apfs_sops = {
	.put_super = apfs_put_super,
};

#define VOLUME_NUMBER	0 /* Hardcode it for now, later add a mount option */

static int apfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct buffer_head *bh, *bh2;
	struct apfs_sb_info *sbi;
	struct apfs_super_block *msb_raw;
	struct apfs_table_raw *vrb_raw;
	struct apfs_volume_checkpoint_sb *vcsb_raw;
	struct apfs_table *vtable;
	struct inode *root;
	u64 vol_id;
	u64 vrb, vb, vcsb = 0;
	int blocksize;
	int i;
	int err = -EINVAL;

	apfs_msg(sb, KERN_NOTICE, "this module is read-only");
	sb->s_flags |= MS_RDONLY;

	/*
	 * For now assume a small blocksize, we only need it so that we can
	 * read the actual blocksize from disk.
	 */
	if (!sb_set_blocksize(sb, APFS_DEFAULT_BLOCKSIZE)) {
		apfs_msg(sb, KERN_ERR, "unable to set blocksize");
		return err;
	}
	bh = sb_bread(sb, APFS_SB_BLOCK);
	if (!bh) {
		apfs_msg(sb, KERN_ERR, "unable to read superblock");
		return err;
	}
	msb_raw = (struct apfs_super_block *)bh->b_data;
	blocksize = le32_to_cpu(msb_raw->s_blksize);
	if (sb->s_blocksize != blocksize) {
		brelse(bh);

		if (!sb_set_blocksize(sb, blocksize)) {
			apfs_msg(sb, KERN_ERR, "bad blocksize %d", blocksize);
			return err;
		}
		bh = sb_bread(sb, APFS_SB_BLOCK);
		if (!bh) {
			apfs_msg(sb, KERN_ERR,
				 "unable to read superblock 2nd time");
			return err;
		}
		msb_raw = (struct apfs_super_block *)bh->b_data;
	}

	sb->s_magic = le32_to_cpu(msb_raw->s_magic);
	if (sb->s_magic != APFS_SUPER_MAGIC) {
		apfs_msg(sb, KERN_ERR, "not an apfs filesystem");
		goto failed_super;
	}

	/* Get the id for the requested volume number */
	if (sizeof(*msb_raw) + 8 * (VOLUME_NUMBER + 1) >= sb->s_blocksize) {
		/* For now we assume that nodesize <= PAGE_SIZE */
		apfs_msg(sb, KERN_ERR, "volume number out of range");
		goto failed_super;
	}
	vol_id = le64_to_cpu(msb_raw->volume_ids[VOLUME_NUMBER]);
	if (vol_id == 0) {
		apfs_msg(sb, KERN_ERR, "requested volume does not exist");
		goto failed_super;
	}

	err = -ENOMEM;
	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		goto failed_super;
	sb->s_fs_info = sbi;
	sbi->s_msb_raw = msb_raw;
	sbi->s_mnode.sb = sb;
	sbi->s_mnode.block_nr = APFS_SB_BLOCK;
	sbi->s_mnode.node_id = le64_to_cpu(msb_raw->s_header.n_block_id);
	sbi->s_mnode.bh = bh;

	/* For now we only support nodesize < PAGE_SIZE */
	sbi->s_nodesize = sb->s_blocksize;
	sbi->s_nodesize_bits = sb->s_blocksize_bits;

	err = -EINVAL;

	/* Get the Volume Root Block */
	vrb = le32_to_cpu(msb_raw->s_volume_index);
	bh2 = sb_bread(sb, vrb);
	if (!bh2) {
		apfs_msg(sb, KERN_ERR, "unable to read volume root block");
		goto failed_vol;
	}
	vrb_raw = (struct apfs_table_raw *)bh2->b_data;

	/* Get the Volume Block */
	vb = le64_to_cpu(vrb_raw->t_sd.t_single_rec);
	vrb_raw = NULL;
	brelse(bh2);
	vtable = apfs_read_table(sb, vb);
	if (!vtable) {
		apfs_msg(sb, KERN_ERR, "unable to read volume block");
		goto failed_vol;
	}

	/* Get the Volume Checkpoint Superblock with id == vol_id */
	for (i = 0; i < vtable->t_records; i++) {
		/* This whole search should become a separate function */
		int len, off;
		__le64 *id, *block;

		len = apfs_table_locate_key(vtable, i, &off);
		id = (__le64 *)(vtable->t_node.bh->b_data + off);
		if (le64_to_cpu(*id) == vol_id) {
			len = apfs_table_locate_data(vtable, i, &off);
			/* The block number is in the second 64 bits of data */
			block = (__le64 *)(vtable->t_node.bh->b_data + off + 8);
			vcsb = le64_to_cpu(*block);
			break;
		}
	}
	apfs_release_table(vtable);

	if (vcsb == 0) {
		apfs_msg(sb, KERN_ERR, "volume not found, likely corruption");
		goto failed_vol;
	}
	bh2 = sb_bread(sb, vcsb);
	if (!bh2) {
		apfs_msg(sb, KERN_ERR, "unable to read volume superblock");
		goto failed_vol;
	}

	vcsb_raw = (struct apfs_volume_checkpoint_sb *)bh2->b_data;
	if (le32_to_cpu(vcsb_raw->v_magic) != APFS_VOL_MAGIC) {
		apfs_msg(sb, KERN_ERR, "wrong magic in volume superblock");
		goto failed_mount;
	}

	sbi->s_vcsb_raw = vcsb_raw;
	sbi->s_vnode.sb = sb;
	sbi->s_vnode.block_nr = vcsb;
	sbi->s_vnode.node_id = vcsb_raw->v_header.n_block_id;
	sbi->s_vnode.bh = bh2;

	/* Print the last write time to verify the mount was successful */
	apfs_msg(sb, KERN_INFO, "volume last modified at %llx",
		 le64_to_cpu(vcsb_raw->v_wtime));
	/* Also the number of files */
	apfs_msg(sb, KERN_INFO, "volume has %llu files and %llu directories",
		 le64_to_cpu(vcsb_raw->v_file_count),
		 le64_to_cpu(vcsb_raw->v_fold_count));

	sb->s_op = &apfs_sops;

	/* Create a shell of a "root inode" for testing the mount */
	err = -ENOMEM;
	root = iget_locked(sb, APFS_ROOT_CNID);
	if (!root) {
		apfs_msg(sb, KERN_ERR, "unable to get root inode");
		goto failed_mount;
	}
	root->i_mode = S_IFDIR;
	unlock_new_inode(root);
	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		apfs_msg(sb, KERN_ERR, "unable to get root dentry");
		goto failed_mount;
	}
	return 0;

failed_mount:
	brelse(bh2);
failed_vol:
	sb->s_fs_info = NULL;
	kfree(sbi);
failed_super:
	brelse(bh);
	return err;
}

static struct dentry *apfs_mount(struct file_system_type *fs_type,
		int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, apfs_fill_super);
}

static struct file_system_type apfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "apfs",
	.mount		= apfs_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("apfs");

static int __init init_apfs_fs(void)
{
	return register_filesystem(&apfs_fs_type);
}

static void __exit exit_apfs_fs(void)
{
	unregister_filesystem(&apfs_fs_type);
}

MODULE_AUTHOR("Ernesto A. Fernandez");
MODULE_DESCRIPTION("Apple File System");
MODULE_LICENSE("GPL");
module_init(init_apfs_fs)
module_exit(exit_apfs_fs)
