// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/inode.c
 *
 * Copyright (C) 2018 Ernesto A. Fernandez <ernesto.mnd.fernandez@gmail.com>
 */

#include <linux/slab.h>
#include "apfs.h"
#include "key.h"

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
	apfs_init_key(APFS_RT_INODE, cnid, NULL /* name */, key);

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
	inode->i_atime.tv_sec = le64_to_cpu(raw_inode->d_atime) / NSEC_PER_SEC;
	inode->i_atime.tv_nsec = le64_to_cpu(raw_inode->d_atime) % NSEC_PER_SEC;
	inode->i_ctime.tv_sec = le64_to_cpu(raw_inode->d_ctime) / NSEC_PER_SEC;
	inode->i_ctime.tv_nsec = le64_to_cpu(raw_inode->d_ctime) % NSEC_PER_SEC;
	inode->i_mtime.tv_sec = le64_to_cpu(raw_inode->d_mtime) / NSEC_PER_SEC;
	inode->i_mtime.tv_nsec = le64_to_cpu(raw_inode->d_mtime) % NSEC_PER_SEC;
	ai->i_crtime = le64_to_cpu(raw_inode->d_crtime); /* Not used for now */

	/* A lot of operations still missing, of course */
	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &apfs_file_inode_operations;
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
