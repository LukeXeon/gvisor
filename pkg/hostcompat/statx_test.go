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
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStatxDescriptorCompatibility(t *testing.T) {
	t.Logf("GOOS=%s statx_allowed=%t", runtime.GOOS, statxAllowed())
	root := t.TempDir()
	path := filepath.Join(root, "file")
	data := []byte("immutable descriptor identity")
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink("file", link); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name, path  string
		flags, kind int
	}{
		{"file", path, unix.O_RDONLY, unix.S_IFREG},
		{"directory", root, unix.O_RDONLY | unix.O_DIRECTORY, unix.S_IFDIR},
		{"opath-file", path, unix.O_PATH, unix.S_IFREG},
		{"opath-symlink", link, unix.O_PATH | unix.O_NOFOLLOW, unix.S_IFLNK},
	} {
		t.Run(item.name, func(t *testing.T) {
			fd, err := unix.Open(item.path, item.flags|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			var got unix.Statx_t
			if err := Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_BASIC_STATS|unix.STATX_BTIME, &got); err != nil {
				t.Fatal(err)
			}
			if got.Mask&unix.STATX_BASIC_STATS != unix.STATX_BASIC_STATS || int(got.Mode)&unix.S_IFMT != item.kind {
				t.Fatalf("invalid mask/type: %+v", got)
			}
			var expected unix.Stat_t
			if err := unix.Fstatat(fd, "", &expected, unix.AT_EMPTY_PATH); err != nil {
				t.Fatal(err)
			}
			if got.Ino != expected.Ino || got.Size != uint64(expected.Size) || got.Mode != uint16(expected.Mode) || got.Uid != expected.Uid || got.Gid != expected.Gid {
				t.Fatalf("descriptor metadata mismatch: %+v vs %+v", got, expected)
			}
			if !statxAllowed() && (got.Mask&unix.STATX_BTIME != 0 || got.Btime.Sec != 0 || got.Btime.Nsec != 0) {
				t.Fatal("birth time fabricated")
			}
		})
	}
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var before, after unix.Statx_t
	if err := Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_BASIC_STATS, &before); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_BASIC_STATS, &after); err != nil || after.Ino != before.Ino || after.Size != uint64(len(data)) || after.Nlink != 0 {
		t.Fatalf("unlinked identity: %+v %v", after, err)
	}
	if err := Statx(-1, "", unix.AT_EMPTY_PATH, unix.STATX_BASIC_STATS, &after); err != unix.EBADF {
		t.Fatalf("bad fd: %v", err)
	}
	if err := Statx(fd, "", unix.AT_EMPTY_PATH, int(unix.STATX__RESERVED), &after); err != unix.EINVAL {
		t.Fatalf("reserved mask: %v", err)
	}
}

func TestStatxFallbackHandlesRelativeLookups(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	dir, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	for _, item := range []struct {
		name  string
		flags int
		kind  int
	}{
		{"file", unix.AT_SYMLINK_NOFOLLOW | unix.AT_NO_AUTOMOUNT, unix.S_IFREG},
		{"link", unix.AT_SYMLINK_NOFOLLOW | unix.AT_NO_AUTOMOUNT, unix.S_IFLNK},
		{"link", 0, unix.S_IFREG},
	} {
		var got unix.Statx_t
		if err := statxFromStat(dir, item.name, item.flags, unix.STATX_BASIC_STATS, &got); err != nil {
			t.Fatalf("%s/%#x: %v", item.name, item.flags, err)
		}
		if int(got.Mode)&unix.S_IFMT != item.kind || got.Mask != unix.STATX_BASIC_STATS {
			t.Fatalf("%s/%#x: %+v", item.name, item.flags, got)
		}
	}
	var got unix.Statx_t
	if err := statxFromStat(dir, "missing", unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS, &got); err != unix.ENOENT {
		t.Fatalf("missing child: %v", err)
	}
}
