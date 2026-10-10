// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hostfd

import (
	"bytes"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/safemem"
)

func TestVectoredReadOffsetsAndEOF(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "read-vectors")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data := bytes.Repeat([]byte{0x5a}, MaxReadWriteIov+3)
	if _, err := file.Write(append([]byte("prefix!"), data...)); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(2, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, len(data))
	blocks := make([]safemem.Block, len(actual))
	for i := range actual {
		blocks[i] = safemem.BlockFromSafeSlice(actual[i : i+1])
	}
	seq := safemem.BlockSeqFromSlice(blocks)
	n, err := Preadv2(int32(file.Fd()), seq, 7, 0)
	if err != nil || n != uint64(len(data)) || !bytes.Equal(actual, data) {
		t.Fatalf("positioned read=(%d,%v), dataEqual=%v", n, err, bytes.Equal(actual, data))
	}
	if pos, err := file.Seek(0, io.SeekCurrent); err != nil || pos != 2 {
		t.Fatalf("positioned read changed offset: (%d,%v)", pos, err)
	}
	if _, err := file.Seek(7, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	clear(actual)
	n, err = Preadv2(int32(file.Fd()), seq, -1, 0)
	if err != nil || n != uint64(len(data)) || !bytes.Equal(actual, data) {
		t.Fatalf("current-offset read=(%d,%v)", n, err)
	}
	if pos, err := file.Seek(0, io.SeekCurrent); err != nil || pos != int64(len(data)+7) {
		t.Fatalf("current-offset read position=(%d,%v)", pos, err)
	}
	if n, err := Preadv2(int32(file.Fd()), seq, -1, 0); n != 0 || err != io.EOF {
		t.Fatalf("end-of-file read=(%d,%v)", n, err)
	}
	clear(actual)
	n, err = Preadv2(int32(file.Fd()), seq, int64(len(data)+5), 0)
	if err != nil || n != 2 || !bytes.Equal(actual[:2], data[:2]) || actual[2] != 0 {
		t.Fatalf("short read=(%d,%v)", n, err)
	}
	if n, err := Preadv2(int32(file.Fd()), seq, 0, 1<<31); n != 0 || err == nil {
		t.Fatalf("unsupported flags read=(%d,%v)", n, err)
	}
}

func TestVectoredReadPipe(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	if _, err := unix.Write(fds[1], []byte("abc")); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, 6)
	seq := safemem.BlockSeqFromSlice([]safemem.Block{
		safemem.BlockFromSafeSlice(actual[:2]),
		safemem.BlockFromSafeSlice(actual[2:]),
	})
	n, err := Preadv2(int32(fds[0]), seq, -1, 0)
	if err != nil || n != 3 || string(actual[:3]) != "abc" || actual[3] != 0 {
		t.Fatalf("pipe short read=(%d,%v), data=%q", n, err, actual)
	}
	if _, err := Preadv2(int32(fds[0]), seq, 0, 0); err != unix.ESPIPE {
		t.Fatalf("positioned pipe read error=%v, want ESPIPE", err)
	}
}

func TestVectoredWriteOffsets(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "vectors")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	// Cross the syscall iovec limit and verify that subsequent calls advance
	// the explicit offset without changing the descriptor's current offset.
	data := bytes.Repeat([]byte{0x5a}, MaxReadWriteIov+3)
	blocks := make([]safemem.Block, len(data))
	for i := range data {
		blocks[i] = safemem.BlockFromSafeSlice(data[i : i+1])
	}
	seq := safemem.BlockSeqFromSlice(blocks)
	n, err := Pwritev2(int32(file.Fd()), seq, 7, 0)
	if err != nil || n != uint64(len(data)) {
		t.Fatalf("positioned write=(%d,%v)", n, err)
	}
	if pos, err := file.Seek(0, 1); err != nil || pos != 0 {
		t.Fatalf("positioned write changed offset: (%d,%v)", pos, err)
	}
	actual, err := os.ReadFile(file.Name())
	if err != nil || !bytes.Equal(actual, append(make([]byte, 7), data...)) {
		t.Fatalf("positioned write data mismatch: %v", err)
	}
	if _, err := file.Seek(2, 0); err != nil {
		t.Fatal(err)
	}
	n, err = Pwritev2(int32(file.Fd()), seq, -1, 0)
	if err != nil || n != uint64(len(data)) {
		t.Fatalf("current-offset write=(%d,%v)", n, err)
	}
	if pos, err := file.Seek(0, 1); err != nil || pos != int64(len(data)+2) {
		t.Fatalf("current-offset write position=(%d,%v)", pos, err)
	}
	actual, err = os.ReadFile(file.Name())
	if err != nil || !bytes.Equal(actual[2:2+len(data)], data) {
		t.Fatalf("current-offset write data mismatch: %v", err)
	}
}

func TestVectoredWriteShortPipe(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	capacity, err := unix.FcntlInt(uintptr(fds[1]), unix.F_GETPIPE_SZ, 0)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{0x37}, capacity*2)
	seq := safemem.BlockSeqFromSlice([]safemem.Block{
		safemem.BlockFromSafeSlice(data[:capacity/2]),
		safemem.BlockFromSafeSlice(data[capacity/2:]),
	})
	n, err := Pwritev2(int32(fds[1]), seq, -1, 0)
	if err != nil || n == 0 || n >= uint64(len(data)) {
		t.Fatalf("short write=(%d,%v), capacity=%d", n, err, capacity)
	}
	actual := make([]byte, n)
	read, err := unix.Read(fds[0], actual)
	if err != nil || read != int(n) || !bytes.Equal(actual, data[:n]) {
		t.Fatalf("short write data=(%d,%v)", read, err)
	}
	if _, err := Pwritev2(int32(fds[1]), seq, 0, 0); err != unix.ESPIPE {
		t.Fatalf("positioned pipe write error=%v, want ESPIPE", err)
	}
}

func TestVectoredWritePreservesFlags(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "flags")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	seq := safemem.BlockSeqFromSlice([]safemem.Block{
		safemem.BlockFromSafeSlice([]byte("a")),
		safemem.BlockFromSafeSlice([]byte("b")),
	})
	// Unknown flags must still reach pwritev2, including ENOSYS on an old
	// kernel, instead of silently becoming an unflagged write.
	n, err := Pwritev2(int32(file.Fd()), seq, 0, 1<<31)
	if n != 0 || err == nil {
		t.Fatalf("unsupported flags write=(%d,%v)", n, err)
	}
	if info, err := file.Stat(); err != nil || info.Size() != 0 {
		t.Fatalf("unsupported flags modified file: %v", err)
	}
}
