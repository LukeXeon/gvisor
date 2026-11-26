// Copyright 2020 The gVisor Authors.
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

package overlay

import (
	"context"

	sentrycontext "gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// PrepareSave implements vfs.FilesystemImplSaveRestoreExtension.PrepareSave.
// Cached dentries are not saved: the list that holds them is not, and a
// restored filesystem resolves their names again.
func (fs *filesystem) PrepareSave(ctx sentrycontext.Context, _ vfs.PrepareSaveOptions) error {
	fs.renameMu.Lock()
	defer fs.renameMu.Unlock()
	fs.evictAllLocked(ctx)
	return nil
}

// BeforeResume implements vfs.FilesystemImplSaveRestoreExtension.BeforeResume.
func (fs *filesystem) BeforeResume(sentrycontext.Context) {}

// CompleteRestore implements
// vfs.FilesystemImplSaveRestoreExtension.CompleteRestore.
func (fs *filesystem) CompleteRestore(sentrycontext.Context, vfs.CompleteRestoreOptions) error {
	return nil
}

func (d *dentry) afterLoad(context.Context) {
	if d.refs.Load() != -1 {
		refs.Register(d)
	}
}

// saveParent is called by stateify.
func (d *dentry) saveParent() *dentry {
	return d.parent.Load()
}

// loadParent is called by stateify.
func (d *dentry) loadParent(_ context.Context, parent *dentry) {
	d.parent.Store(parent)
}

// saveAccessACL is called by stateify.
func (d *dentry) saveAccessACL() *vfs.PosixACL {
	return d.accessACL.Load()
}

// loadAccessACL is called by stateify.
func (d *dentry) loadAccessACL(_ context.Context, accessACL *vfs.PosixACL) {
	d.accessACL.Store(accessACL)
}

// saveDefaultACL is called by stateify.
func (d *dentry) saveDefaultACL() *vfs.PosixACL {
	return d.defaultACL.Load()
}

// loadDefaultACL is called by stateify.
func (d *dentry) loadDefaultACL(_ context.Context, defaultACL *vfs.PosixACL) {
	d.defaultACL.Store(defaultACL)
}
