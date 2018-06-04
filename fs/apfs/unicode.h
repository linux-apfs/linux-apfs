/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  linux/fs/apfs/unicode.h
 *
 * Copyright (C) 2018 Ernesto A. Fernández <ernesto.mnd.fernandez@gmail.com>
 */

#ifndef _APFS_UNICODE_H
#define _APFS_UNICODE_H

#include <linux/nls.h>

/*
 * This structure helps apfs_normalize_next() to retrieve one normalized
 * (and case-folded) UTF-32 character at a time from a UTF-8 string.
 */
struct apfs_unicursor {
	const char *utf8next;	/* Next UTF-8 char to normalize */

	unicode_t *buf;	/* Buffer to save the work until the next starter */
	int buf_len;	/* Length of the buffer */
	int buf_off;	/* Offset in buf of the next normalized char */
};

extern struct apfs_unicursor *apfs_init_unicursor(const char *utf8str);
extern void apfs_free_unicursor(struct apfs_unicursor *cursor);
extern int apfs_normalize_next(struct apfs_unicursor *cursor, unicode_t *next);

#endif	/* _APFS_UNICODE_H */
