// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/apfs/file.c
 *
 * Copyright (C) 2018 Ernesto A. Fernandez <ernesto.mnd.fernandez@gmail.com>
 */

#include "apfs.h"

const struct inode_operations apfs_file_inode_operations = {
	.listxattr	= apfs_listxattr,
};
