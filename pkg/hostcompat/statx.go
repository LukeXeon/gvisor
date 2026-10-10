// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package hostcompat

import (
	"golang.org/x/sys/unix"
)

// Statx calls statx(2) when the host permits it. Otherwise, or when the host
// kernel lacks statx, it answers the request with fstatat(2), which every
// supported host permits for both descriptor (AT_EMPTY_PATH) and
// dirfd-relative lookups. The fallback reports only the real basic statistics
// and never fabricates a birth time.
func Statx(dirfd int, path string, flags, mask int, result *unix.Statx_t) error {
	if statxAllowed() {
		if err := unix.Statx(dirfd, path, flags, mask, result); err != unix.ENOSYS {
			return err
		}
	}
	return statxFromStat(dirfd, path, flags, mask, result)
}

func statxFromStat(dirfd int, path string, flags, mask int, result *unix.Statx_t) error {
	const syncFlags = unix.AT_STATX_FORCE_SYNC | unix.AT_STATX_DONT_SYNC
	const validFlags = unix.AT_EMPTY_PATH | unix.AT_SYMLINK_NOFOLLOW | unix.AT_NO_AUTOMOUNT | syncFlags
	if flags&^validFlags != 0 || flags&syncFlags == syncFlags || uint32(mask)&unix.STATX__RESERVED != 0 {
		return unix.EINVAL
	}
	if result == nil {
		return unix.EFAULT
	}
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, path, &st, flags&^syncFlags); err != nil {
		return err
	}
	*result = unix.Statx_t{
		Mask: unix.STATX_BASIC_STATS, Blksize: uint32(st.Blksize), Nlink: uint32(st.Nlink),
		Uid: st.Uid, Gid: st.Gid, Mode: uint16(st.Mode), Ino: st.Ino,
		Size: uint64(st.Size), Blocks: uint64(st.Blocks),
		Dev_major: unix.Major(uint64(st.Dev)), Dev_minor: unix.Minor(uint64(st.Dev)),
		Rdev_major: unix.Major(uint64(st.Rdev)), Rdev_minor: unix.Minor(uint64(st.Rdev)),
		Atime: unix.StatxTimestamp{Sec: st.Atim.Sec, Nsec: uint32(st.Atim.Nsec)},
		Mtime: unix.StatxTimestamp{Sec: st.Mtim.Sec, Nsec: uint32(st.Mtim.Nsec)},
		Ctime: unix.StatxTimestamp{Sec: st.Ctim.Sec, Nsec: uint32(st.Ctim.Nsec)},
	}
	return nil
}
