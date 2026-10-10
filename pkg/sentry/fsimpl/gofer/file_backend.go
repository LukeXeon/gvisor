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

package gofer

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// FileBackend optionally supplies directfs host file operations. It does not
// implement guest permission checks or change the LISAFS protocol. Root takes
// ownership of fd on both success and failure.
type FileBackend interface {
	Root(fd int, readonly bool) (BackendFile, error)
}

// BackendDirent describes a logical directory entry backed by a host inode.
type BackendDirent struct {
	Name string
	Dev  uint64
	Ino  uint64
	Type uint8
}

// BackendFile owns a host control FD. Native data FDs returned by Open and Create
// transfer to the caller and retain the normal directfs data/mapping contract.
// Stat may use a caller-owned data FD for the same file, or FD() otherwise.
// Implementations provide attributes at the file source, not a second VFS.
type BackendFile interface {
	FD() int
	Close()
	Stat(fd int, stat *unix.Statx_t) error
	Lookup(name string) (BackendFile, error)
	Open(flags uint32) (int, error)
	Create(name string, flags uint32, mode linux.FileMode, uid auth.KUID, gid auth.KGID) (BackendFile, int, error)
	Mkdir(name string, mode linux.FileMode, uid auth.KUID, gid auth.KGID) (BackendFile, error)
	Mknod(name string, mode linux.FileMode, uid auth.KUID, gid auth.KGID, minor, major uint32) (BackendFile, error)
	Symlink(name, target string, uid auth.KUID, gid auth.KGID) (BackendFile, error)
	Link(target BackendFile, name string) (BackendFile, error)
	Unlink(name string, flags uint32) error
	UnlinkIfSame(name string, dev, ino uint64) error
	Rename(oldName string, newParent BackendFile, newName string, flags uint32) error
	Chmod(mode uint32) error
	SetStat(stat *linux.Statx, clearPrivs bool) (uint32, error)
	ReadDir() ([]BackendDirent, error)
	Readlink() (string, error)
	GetXattr(name string, size uint64) (string, error)
	SetXattr(name, value string, flags uint32) error
	ListXattr(size uint64) ([]string, error)
	RemoveXattr(name string) error
	DropCapability() error
	Sync(fd int, dataOnly bool) error
}
