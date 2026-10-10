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

import "golang.org/x/sys/unix"

// Syscall preserves the scheduler-aware unix.Syscall contract.
//
//go:uintptrescapes
func Syscall(trap, a1, a2, a3 uintptr) (uintptr, uintptr, unix.Errno) {
	if trap == unix.SYS_MEMBARRIER && !membarrierAllowed() {
		return ^uintptr(0), 0, unix.ENOSYS
	}
	return unix.Syscall(trap, a1, a2, a3)
}

// RawSyscall preserves the raw call contract without initialization. Pointer
// arguments retain their Go objects for the complete call.
//
//go:uintptrescapes
//go:nosplit
func RawSyscall(trap, a1, a2, a3 uintptr) (uintptr, uintptr, unix.Errno) {
	if trap == unix.SYS_MEMBARRIER && !membarrierAllowed() {
		return ^uintptr(0), 0, unix.ENOSYS
	}
	return unix.RawSyscall(trap, a1, a2, a3)
}

// Syscall6 preserves the existing iovec pointer and flags. Zero-flag vector I/O
// may use classic syscalls; other calls and nonzero flags pass through unchanged.
//
//go:uintptrescapes
func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, unix.Errno) {
	if a6 != 0 || (trap != unix.SYS_PREADV2 && trap != unix.SYS_PWRITEV2) {
		return unix.Syscall6(trap, a1, a2, a3, a4, a5, a6)
	}
	if !preferClassicVectors() {
		r1, r2, errno := unix.Syscall6(trap, a1, a2, a3, a4, a5, a6)
		if errno != unix.ENOSYS {
			return r1, r2, errno
		}
	}
	return classicVectorCall(trap, a1, a2, a3, a4, a5)
}

func classicVectorCall(trap, fd, iovs, count, offset, high uintptr) (uintptr, uintptr, unix.Errno) {
	if offset == ^uintptr(0) {
		if trap == unix.SYS_PREADV2 {
			trap = unix.SYS_READV
		} else {
			trap = unix.SYS_WRITEV
		}
	} else if trap == unix.SYS_PREADV2 {
		trap = unix.SYS_PREADV
	} else {
		trap = unix.SYS_PWRITEV
	}
	return unix.Syscall6(trap, fd, iovs, count, offset, high, 0)
}
