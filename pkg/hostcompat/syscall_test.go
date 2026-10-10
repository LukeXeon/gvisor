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
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestSyscallKeepsPointerAlive(t *testing.T) {
	for _, sixArguments := range []bool{false, true} {
		name := "Syscall"
		if sixArguments {
			name = "Syscall6"
		}
		t.Run(name, func(t *testing.T) {
			var fds [2]int
			if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fds[0])
			defer unix.Close(fds[1])
			collected := make(chan struct{})
			buffer := new([65536]byte)
			runtime.SetFinalizer(buffer, func(*[65536]byte) { close(collected) })
			type writerResult struct {
				collected bool
				err       error
			}
			written := make(chan writerResult, 1)
			go func() {
				for n := 0; n < 8; n++ {
					runtime.GC()
					runtime.Gosched()
					time.Sleep(time.Millisecond)
				}
				early := false
				select {
				case <-collected:
					early = true
				default:
				}
				_, err := unix.Write(fds[1], []byte{1})
				written <- writerResult{early, err}
			}()
			// The syscall alone must retain the buffer. Accessing it afterward
			// would mask an early collection in the wrapper.
			var n uintptr
			var errno unix.Errno
			if sixArguments {
				n, _, errno = Syscall6(unix.SYS_READ, uintptr(fds[0]), uintptr(unsafe.Pointer(buffer)), 1, 0, 0, 0)
			} else {
				n, _, errno = Syscall(unix.SYS_READ, uintptr(fds[0]), uintptr(unsafe.Pointer(buffer)), 1)
			}
			result := <-written
			if errno != 0 || n != 1 || result.err != nil {
				t.Fatalf("read=%d errno=%v write=%v", n, errno, result.err)
			}
			if result.collected {
				t.Fatal("Go buffer finalized before the blocking syscall returned")
			}
		})
	}
}

func TestRawSyscallAndMembarrierPolicy(t *testing.T) {
	got, _, errno := RawSyscall(unix.SYS_GETPID, 0, 0, 0)
	if errno != 0 || int(got) != unix.Getpid() {
		t.Fatalf("getpid=%d errno=%v", got, errno)
	}
	allocations := testing.AllocsPerRun(100, func() { RawSyscall(unix.SYS_GETPID, 0, 0, 0) })
	if allocations != 0 {
		t.Fatalf("raw syscall allocations=%g", allocations)
	}
	_, _, raw := RawSyscall(unix.SYS_MEMBARRIER, 0, 0, 0)
	_, _, scheduled := Syscall(unix.SYS_MEMBARRIER, 0, 0, 0)
	if !membarrierAllowed() && (raw != unix.ENOSYS || scheduled != unix.ENOSYS) {
		t.Fatalf("blocked query: %v %v", raw, scheduled)
	}
	if raw != scheduled {
		t.Fatalf("query paths disagree: %v %v", raw, scheduled)
	}
}

func BenchmarkRawSyscall(b *testing.B) {
	b.Run("native", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			unix.RawSyscall(unix.SYS_GETPID, 0, 0, 0)
		}
	})
	b.Run("compat", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			RawSyscall(unix.SYS_GETPID, 0, 0, 0)
		}
	})
}
