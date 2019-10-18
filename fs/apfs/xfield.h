/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/xfield.h
 *
 * Copyright (C) 2019 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_XFIELD_H
#define _APFS_XFIELD_H

#include <linux/types.h>

/* Extended field types for dentries */
#define APFS_DREC_EXT_TYPE_SIBLING_ID 1

/* Extended field types for inodes */
#define APFS_INO_EXT_TYPE_SNAP_XID 1
#define APFS_INO_EXT_TYPE_DELTA_TREE_OID 2
#define APFS_INO_EXT_TYPE_DOCUMENT_ID 3
#define APFS_INO_EXT_TYPE_NAME 4
#define APFS_INO_EXT_TYPE_PREV_FSIZE 5
#define APFS_INO_EXT_TYPE_RESERVED_6 6
#define APFS_INO_EXT_TYPE_FINDER_INFO 7
#define APFS_INO_EXT_TYPE_DSTREAM 8
#define APFS_INO_EXT_TYPE_RESERVED_9 9
#define APFS_INO_EXT_TYPE_DIR_STATS_KEY 10
#define APFS_INO_EXT_TYPE_FS_UUID 11
#define APFS_INO_EXT_TYPE_RESERVED_12 12
#define APFS_INO_EXT_TYPE_SPARSE_BYTES 13
#define APFS_INO_EXT_TYPE_RDEV 14

/* Extended field flags */
#define APFS_XF_DATA_DEPENDENT		0x01
#define APFS_XF_DO_NOT_COPY		0x02
#define APFS_XF_RESERVED_4		0x04
#define APFS_XF_CHILDREN_INHERIT	0x08
#define APFS_XF_USER_FIELD		0x10
#define APFS_XF_SYSTEM_FIELD		0x20
#define APFS_XF_RESERVED_40		0x40
#define APFS_XF_RESERVED_80		0x80

/*
 * Structure used to store the number and size of an xfield collection
 */
struct apfs_xf_blob {
	__le16 xf_num_exts;
	__le16 xf_used_data;
	u8 xf_data[];
} __packed;

/*
 * Structure used to describe an extended field
 */
struct apfs_x_field {
	u8 x_type;
	u8 x_flags;
	__le16 x_size;
} __packed;

extern int apfs_find_xfield(u8 *xfields, int len, u8 xtype, char **xval);

#endif	/* _APFS_XFIELD_H */
