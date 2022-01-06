/*
 *  Copyright (C) 2017 Samsung Electronics Co., Ltd.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _FSCRYPTO_SDP_IOCTL_H
#define _FSCRYPTO_SDP_IOCTL_H

#ifdef CONFIG_FSCRYPT_SDP
struct dek_arg_set_sensitive {
	int engine_id;
};

struct dek_arg_add_chamber {
	int engine_id;
};

struct dek_arg_sdp_info {
	int engine_id;
	int sdp_enabled;
	int is_sensitive;
	int is_chamber;
	unsigned int type;
};
/*
 * Must be implemented to every file system wanting to use SDP
 */
#define FS_IOC_GET_SDP_INFO     _IOR('l', 0x11, struct dek_arg_sdp_info)
#define FS_IOC_SET_SENSITIVE    _IOW('l', 0x15, struct dek_arg_set_sensitive)
#define FS_IOC_SET_PROTECTED    _IOW('l', 0x16, __u32)
#define FS_IOC_ADD_CHAMBER      _IOW('l', 0x17, struct dek_arg_add_chamber)
#define FS_IOC_REMOVE_CHAMBER   _IOW('l', 0x18, __u32)

int fscrypt_sdp_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
#endif

#endif	/* _FSCRYPTO_SDP_IOCTL_H */
