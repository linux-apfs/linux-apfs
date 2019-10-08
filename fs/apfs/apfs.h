/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/apfs.h
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_H
#define _APFS_H

#include <linux/time64.h>
#include <asm/byteorder.h>
#include <asm/div64.h>

#define APFS_MODULE_ID_STRING	"linux-apfs by EA Fernández"

#define EFSBADCRC	EBADMSG		/* Bad CRC detected */
#define EFSCORRUPTED	EUCLEAN		/* Filesystem is corrupted */

/**
 * apfs_timestamp - Convert a timespec structure into an on-disk timestamp
 * @ts: the timespec structure
 */
static inline __le64 apfs_timestamp(struct timespec64 ts)
{
	return cpu_to_le64(ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec);
}

/**
 * apfs_timespec - Convert an on-disk timestamp into a timespec structure
 * @timestamp: the on-disk timestamp (nanoseconds since the epoch)
 */
static inline struct timespec64 apfs_timespec(__le64 timestamp)
{
	struct timespec64 ts;
	u64 secs = le64_to_cpu(timestamp);

	ts.tv_nsec = do_div(secs, NSEC_PER_SEC);
	ts.tv_sec = secs;
	return ts;
}

/*
 * Inode and file operations
 */

/* file.c */
extern const struct file_operations apfs_file_operations;
extern const struct inode_operations apfs_file_inode_operations;

/* namei.c */
extern const struct inode_operations apfs_dir_inode_operations;
extern const struct inode_operations apfs_special_inode_operations;
extern const struct dentry_operations apfs_dentry_operations;

/* symlink.c */
extern const struct inode_operations apfs_symlink_inode_operations;

#endif	/* _APFS_H */
