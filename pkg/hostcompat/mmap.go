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
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"gvisor.dev/gvisor/pkg/hostarch"
)

var systemMMapMinAddr = sync.OnceValue(loadMMapMinAddr)

// SystemMMapMinAddr returns the cached host mapping floor. Linux keeps the
// original initialization errors; Android may hide this procfs setting.
func SystemMMapMinAddr() hostarch.Addr { return hostarch.Addr(systemMMapMinAddr()) }

func loadMMapMinAddr() uint64 {
	const source = "/proc/sys/vm/mmap_min_addr"
	data, err := os.ReadFile(source)
	if err != nil {
		if tolerateMMapMinAddrFailure() {
			return 4096
		}
		panic(fmt.Sprintf("couldn't open %s: %v", source, err))
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		if tolerateMMapMinAddrFailure() {
			return 4096
		}
		panic(fmt.Sprintf("couldn't parse %s from %s: %v", string(data), source, err))
	}
	return value
}
