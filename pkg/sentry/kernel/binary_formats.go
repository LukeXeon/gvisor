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

package kernel

import (
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/loader"
)

// SetBinaryFormatHandler installs a kernel-scoped interpreter registry before
// any tasks start. The handler is supplied by the embedding runtime.
func (k *Kernel) SetBinaryFormatHandler(handler loader.BinaryFormatHandler) error {
	k.extMu.Lock()
	defer k.extMu.Unlock()
	if k.started {
		return linuxerr.EBUSY
	}
	k.binaryFormats = handler
	return nil
}
