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

// Package hostcompat wraps host system calls whose availability differs
// between Linux and Android app processes.
//
// The Android app seccomp policy raises SIGSYS for calls it does not allow
// (statx before API 30, membarrier before API 29), so these calls
// cannot simply be attempted and their ENOSYS handled. Old Android kernels also
// lack preadv2/pwritev2. Callers keep the upstream API signatures; the
// per-platform permission policy lives in policy_*.go, and fallbacks only
// cover the argument shapes that the sentry and gofer actually use.
package hostcompat
