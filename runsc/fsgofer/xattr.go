// Copyright 2026 The gVisor Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// limitations under the License.

package fsgofer

import (
	"bytes"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

type XattrProvider interface {
	Get(h HostFile, name string, size uint32, getValueBuf func(uint32) []byte) (uint16, error)

	Set(h HostFile, name string, value string, flags uint32) error

	List(h HostFile, size uint64) ([]string, error)

	Remove(h HostFile, name string) error

	NotifyInodeCreated(dev, ino uint64)

	NotifyInodeUnlinked(dev, ino uint64)
}

type HostFile struct {
	FD int

	Path string

	OPath bool
}

func (h HostFile) DevIno() (uint64, uint64, error) {
	var st unix.Stat_t
	if err := unix.Fstat(h.FD, &st); err != nil {
		return 0, 0, err
	}
	return uint64(st.Dev), st.Ino, nil
}

type hostXattrProvider struct{}

func NewHostXattrProvider() XattrProvider { return hostXattrProvider{} }

func (hostXattrProvider) Get(h HostFile, name string, size uint32, getValueBuf func(uint32) []byte) (uint16, error) {
	if size > linux.XATTR_SIZE_MAX || size == 0 {
		size = linux.XATTR_SIZE_MAX
	}
	data := getValueBuf(size)
	if h.OPath {
		xattrSize, err := unix.Lgetxattr(h.Path, name, data)
		return uint16(xattrSize), err
	}
	xattrSize, err := unix.Fgetxattr(h.FD, name, data)
	return uint16(xattrSize), err
}

func (hostXattrProvider) Set(h HostFile, name string, value string, flags uint32) error {
	if h.OPath {
		return unix.Lsetxattr(h.Path, name, []byte(value), int(flags))
	}
	return unix.Fsetxattr(h.FD, name, []byte(value), int(flags))
}

func (hostXattrProvider) List(h HostFile, size uint64) ([]string, error) {
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
	return parseXattrNames(data[:sz]), nil
}

func (hostXattrProvider) Remove(h HostFile, name string) error {
	if h.OPath {
		return unix.Lremovexattr(h.Path, name)
	}
	return unix.Fremovexattr(h.FD, name)
}

func (hostXattrProvider) NotifyInodeCreated(uint64, uint64) {}

func (hostXattrProvider) NotifyInodeUnlinked(uint64, uint64) {}

func hostListXattr(h HostFile, data []byte) (int, error) {
	if h.OPath {
		return unix.Llistxattr(h.Path, data)
	}
	return unix.Flistxattr(h.FD, data)
}

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
