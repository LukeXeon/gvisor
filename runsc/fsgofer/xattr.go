// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fsgofer

import (
	"bytes"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// XattrProvider is the pluggable storage-policy point for extended
// attributes. When Config.XattrProvider is set, controlFDLisa routes every
// xattr operation through the provider and reports inode-lifecycle events
// to it, following the protocol below; when nil, the stock inline host
// syscalls in lisafs.go run unchanged. All semantics (permissions, size
// probing, error codes on the wire) belong to the client (sentry);
// providers only choose where attribute bytes live. Implementations must be
// safe for concurrent use.
//
// Inode lifecycle protocol (stale-state elimination, mirroring Samba's
// vfs_xattr_tdb):
//
//   - NotifyInodeCreated is called after an operation minted a fresh inode
//     (open(O_CREAT|O_EXCL), mkdir, mknod, symlink). Any state stored for a
//     previous life of that inode number must be dropped, so inode reuse
//     cannot resurrect stale attributes.
//   - NotifyInodeUnlinked is called after unlink/rmdir removed the last
//     known directory entry of an inode: always for rmdir, and for files
//     only when the pre-unlink stat reported st_nlink == 1 (entries held
//     alive by other links keep their attributes). Renames are not
//     reported: keys are inode numbers, so renamed entries need no action,
//     and an inode displaced by a rename overwrite has no reachable name
//     until its inode number is reborn (covered by the create report).
type XattrProvider interface {
	// Get returns the value of name on h, writing it into the buffer
	// returned by getValueBuf (which must be requested with the full value
	// size) and returning the number of bytes written. Mirrors
	// lisafs.ControlFDImpl.GetXattr.
	Get(h HostFile, name string, size uint32, getValueBuf func(uint32) []byte) (uint16, error)

	// Set sets name to value on h. Mirrors lisafs.ControlFDImpl.SetXattr.
	Set(h HostFile, name string, value string, flags uint32) error

	// List returns the attribute names on h. Mirrors
	// lisafs.ControlFDImpl.ListXattr.
	List(h HostFile, size uint64) ([]string, error)

	// Remove removes name from h. Mirrors
	// lisafs.ControlFDImpl.RemoveXattr.
	Remove(h HostFile, name string) error

	// NotifyInodeCreated reports that a fresh inode was just minted on
	// dev (best-effort; see the protocol above). dev is the raw host
	// dev_t (stat st_dev), matching HostFile.DevIno.
	NotifyInodeCreated(dev, ino uint64)

	// NotifyInodeUnlinked reports that the last known directory entry for
	// the inode was removed (best-effort; see the protocol above).
	NotifyInodeUnlinked(dev, ino uint64)
}

// HostFile is the stock host view of the file an xattr operation applies
// to. OPath files (sockets, symlinks) are held as O_PATH FDs for which
// f*xattr(2) fails with EBADF; Path carries the host path for the L*xattr
// family instead.
type HostFile struct {
	// FD is the host file descriptor.
	FD int

	// Path is the host path of the file (valid whenever the control FD
	// exists; used only for OPath files).
	Path string

	// OPath is true for sockets and symlinks.
	OPath bool
}

// DevIno returns the device and inode numbers of h (the Samba file_id key).
func (h HostFile) DevIno() (uint64, uint64, error) {
	var st unix.Stat_t
	if err := unix.Fstat(h.FD, &st); err != nil {
		return 0, 0, err
	}
	return uint64(st.Dev), st.Ino, nil
}

// hostXattrProvider is the stock host-syscall XattrProvider: the same
// syscalls the inline (nil-provider) path in lisafs.go applies. Injected
// providers use it as their host arm; stock connections never instantiate
// it (they run the inline path directly).
type hostXattrProvider struct{}

// NewHostXattrProvider returns the stock host-syscall XattrProvider.
// Composing providers should route their host attempts through it.
func NewHostXattrProvider() XattrProvider { return hostXattrProvider{} }

// Get implements XattrProvider.Get.
func (hostXattrProvider) Get(h HostFile, name string, size uint32, getValueBuf func(uint32) []byte) (uint16, error) {
	// getxattr(2) called with size 0 should return the attribute size. As a
	// result, we need to return the entire attribute here so that the sentry
	// can return the correct value.
	if size > linux.XATTR_SIZE_MAX || size == 0 {
		size = linux.XATTR_SIZE_MAX
	}
	data := getValueBuf(size)
	if h.OPath {
		// Sockets and symlinks use O_PATH host FDs. However, fgetxattr(2) fails
		// with EBADF for O_PATH FDs. Use lgetxattr(2) instead.
		xattrSize, err := unix.Lgetxattr(h.Path, name, data)
		return uint16(xattrSize), err
	}
	xattrSize, err := unix.Fgetxattr(h.FD, name, data)
	return uint16(xattrSize), err
}

// Set implements XattrProvider.Set.
func (hostXattrProvider) Set(h HostFile, name string, value string, flags uint32) error {
	if h.OPath {
		// Sockets and symlinks use O_PATH host FDs. However, fsetxattr(2) fails
		// with EBADF for O_PATH FDs. Use lsetxattr(2) instead.
		return unix.Lsetxattr(h.Path, name, []byte(value), int(flags))
	}
	return unix.Fsetxattr(h.FD, name, []byte(value), int(flags))
}

// List implements XattrProvider.List.
func (hostXattrProvider) List(h HostFile, size uint64) ([]string, error) {
	// listxattr(2) called with size 0 should return the list size. As a result,
	// we need to return the entire list here so that the sentry can return the
	// correct value.
	if size > linux.XATTR_LIST_MAX || size == 0 {
		size = linux.XATTR_LIST_MAX
	}
	bPtr := listXattrBufPool.Get().(*[]byte)
	defer listXattrBufPool.Put(bPtr)
	data := (*bPtr)[:size]
	sz, err := hostListXattr(h, data)
	if err != nil {
		return nil, err
	}
	// parseXattrNames copies the strings, so it is safe to run before the
	// pooled buffer returns via defer.
	return parseXattrNames(data[:sz]), nil
}

// Remove implements XattrProvider.Remove.
func (hostXattrProvider) Remove(h HostFile, name string) error {
	if h.OPath {
		// Sockets and symlinks use O_PATH host FDs. However, fremovexattr(2) fails
		// with EBADF for O_PATH FDs. Use lremovexattr(2) instead.
		return unix.Lremovexattr(h.Path, name)
	}
	return unix.Fremovexattr(h.FD, name)
}

// NotifyInodeCreated implements XattrProvider.NotifyInodeCreated.
func (hostXattrProvider) NotifyInodeCreated(uint64, uint64) {}

// NotifyInodeUnlinked implements XattrProvider.NotifyInodeUnlinked.
func (hostXattrProvider) NotifyInodeUnlinked(uint64, uint64) {}

func hostListXattr(h HostFile, data []byte) (int, error) {
	if h.OPath {
		// Sockets and symlinks use O_PATH host FDs. However, flistxattr(2) fails
		// with EBADF for O_PATH FDs. Use llistxattr(2) instead.
		return unix.Llistxattr(h.Path, data)
	}
	return unix.Flistxattr(h.FD, data)
}

// listXattrBufPool is the package-level pool declared in lisafs.go; the
// host provider reuses it so the two paths share one buffer set.

func parseXattrNames(data []byte) []string {
	var names []string
	for len(data) > 0 {
		i := bytes.IndexByte(data, 0)
		if i < 0 {
			break
		}
		names = append(names, string(data[:i]))
		data = data[i+1:]
	}
	return names
}
