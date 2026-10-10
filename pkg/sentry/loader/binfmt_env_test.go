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
	"reflect"
	"testing"
)

func TestAddInterpreterEnv(t *testing.T) {
	original := []string{"HOME=/root", "BOX64_DYNACACHE_FOLDER=/tmp/other", "PATH=/bin"}
	got, err := addInterpreterEnv(original, []string{"BOX64_DYNACACHE_FOLDER=/var/cache/x64loader", "BOX64_DYNACACHE=1"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"HOME=/root", "PATH=/bin", "BOX64_DYNACACHE_FOLDER=/var/cache/x64loader", "BOX64_DYNACACHE=1"}
	if !reflect.DeepEqual(got, want) || original[1] != "BOX64_DYNACACHE_FOLDER=/tmp/other" {
		t.Fatalf("interpreter env = %q, original = %q", got, original)
	}
	if _, err := addInterpreterEnv(original, []string{"=bad"}); err == nil {
		t.Fatal("empty environment key accepted")
	}
}
