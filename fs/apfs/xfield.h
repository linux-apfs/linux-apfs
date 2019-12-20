/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_XFIELD_H
#define _APFS_XFIELD_H

#include <linux/types.h>
#include "apfs_raw.h"

extern int apfs_find_xfield(u8 *xfields, int len, u8 xtype, char **xval);
extern int apfs_init_xfields(u8 *buffer, int buflen);
extern int apfs_insert_xfield(u8 *buffer, int buflen,
			      const struct apfs_x_field *xkey,
			      const void *xval);

#endif	/* _APFS_XFIELD_H */
