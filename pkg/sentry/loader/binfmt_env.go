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

package loader

import (
	"strings"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

func addInterpreterEnv(original, additions []string) ([]string, error) {
	out := append([]string(nil), original...)
	for _, addition := range additions {
		sep := strings.IndexByte(addition, '=')
		if sep <= 0 || strings.IndexByte(addition, 0) >= 0 {
			return nil, linuxerr.EINVAL
		}
		key := addition[:sep+1]
		n := 0
		for _, old := range out {
			if !strings.HasPrefix(old, key) {
				out[n] = old
				n++
			}
		}
		out = append(out[:n], addition)
	}
	return out, nil
}
