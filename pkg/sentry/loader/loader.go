// Copyright 2018 The gVisor Authors.
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

// Package loader loads an executable file into a MemoryManager.
package loader

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"

	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/linux/errno"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/timing"
	"gvisor.dev/gvisor/pkg/usermem"
)

// LoadArgs holds specifications for an executable file to be loaded.
type LoadArgs struct {
	// MemoryManager is the memory manager to load the executable into.
	MemoryManager *mm.MemoryManager

	// RemainingTraversals is the maximum number of symlinks to follow to
	// resolve Filename. This counter is passed by reference to keep it
	// updated throughout the call stack.
	RemainingTraversals *uint

	// ResolveFinal indicates whether the final link of Filename should be
	// resolved, if it is a symlink.
	ResolveFinal bool

	// Filename is the path for the executable.
	Filename string

	// File is an open FD of the executable. If File is not nil, then File will
	// be loaded and Filename will be ignored.
	//
	// The caller is responsible for checking that the user can execute this file.
	File *vfs.FileDescription

	// BinaryFormats handles formats registered outside the kernel package.
	BinaryFormats BinaryFormatHandler

	// Root is the current filesystem root.
	Root vfs.VirtualDentry

	// WorkingDir is the current working directory.
	WorkingDir vfs.VirtualDentry

	// If AfterOpen is not nil, it is called after every successful call to
	// Opener.OpenPath().
	AfterOpen func(f *vfs.FileDescription)

	// CloseOnExec indicates that the executable (or one of its parent
	// directories) was opened with O_CLOEXEC. If the executable is an
	// interpreter script, then cause an ENOENT error to occur, since the
	// script would otherwise be inaccessible to the interpreter.
	CloseOnExec bool

	// Argv is the vector of arguments to pass to the executable.
	Argv []string

	// Envv is the vector of environment variables to pass to the
	// executable.
	Envv []string

	// Features specifies the CPU feature set for the executable.
	Features cpuid.FeatureSet

	// NoNewPrivs is the prctl NO_NEW_PRIVS state of the calling task.
	NoNewPrivs bool

	// StopPrivGain indicates whether to deny privilege elevation for reasons beyond NO_NEW_PRIVS.
	StopPrivGain bool

	// AllowSUID indicates whether to allow ID elevation during execve.
	AllowSUID bool

	// StartupTimeline tracks this load as part of overall sandbox startup.
	// Only set when loading the initial task image of the root container.
	StartupTimeline *timing.Timeline
}

// BinaryFormatHandler participates in the normal executable traversal. The
// handler returns nil for no match. If InterpreterFile is set, ownership of
// that reference transfers to the loader; on error it remains with the handler.
type BinaryFormatHandler interface {
	Match(ctx context.Context, header []byte, filename string, argv []string, file *vfs.FileDescription) (*BinaryFormatMatch, error)
}

// BinaryFormatMatch describes one interpreter rewrite. Argv contains the
// complete argument vector for the interpreter. OpenBinary requests AT_EXECFD
// and CredentialsFromBinary selects the original executable's credentials.
type BinaryFormatMatch struct {
	Interpreter     string
	InterpreterFile *vfs.FileDescription
	Argv            []string
	// EnvAdd contains key=value entries installed only for the interpreter.
	// Each entry replaces a matching key in the original environment.
	EnvAdd                []string
	OpenBinary            bool
	CredentialsFromBinary bool
}

// openPath opens args.Filename and checks that it is valid for loading.
//
// openPath returns an *fs.Dirent and *fs.File for args.Filename, which is not
// installed in the Task FDTable. The caller takes ownership of both.
//
// args.Filename must be a readable, executable, regular file.
func openPath(ctx context.Context, args LoadArgs) (*vfs.FileDescription, error) {
	if args.Filename == "" {
		ctx.Infof("cannot open empty name")
		return nil, linuxerr.ENOENT
	}

	// TODO(gvisor.dev/issue/160): Linux requires only execute permission,
	// not read. However, our backing filesystems may prevent us from reading
	// the file without read permission. Additionally, a task with a
	// non-readable executable has additional constraints on access via
	// ptrace and procfs.
	opts := vfs.OpenOptions{
		Flags:    linux.O_RDONLY,
		FileExec: true,
	}
	vfsObj := args.Root.Mount().Filesystem().VirtualFilesystem()
	creds := auth.CredentialsFromContext(ctx)
	path := fspath.Parse(args.Filename)
	pop := &vfs.PathOperation{
		Root:               args.Root,
		Start:              args.WorkingDir,
		Path:               path,
		FollowFinalSymlink: args.ResolveFinal,
	}
	if path.Absolute {
		pop.Start = args.Root
	}
	fd, err := vfsObj.OpenAt(ctx, creds, pop, &opts)
	if err != nil {
		return nil, err
	}
	if args.AfterOpen != nil {
		args.AfterOpen(fd)
	}
	return fd, nil
}

// checkIsRegularFile prevents us from trying to execute a directory, pipe, etc.
func checkIsRegularFile(ctx context.Context, fd *vfs.FileDescription, filename string) error {
	stat, err := fd.Stat(ctx, vfs.StatOptions{})
	if err != nil {
		return err
	}
	if t := linux.FileMode(stat.Mode).FileType(); t != linux.ModeRegular {
		ctx.Infof("%q is not a regular file: %v", filename, t)
		return linuxerr.EACCES
	}
	return nil
}

// allocStack allocates and maps a stack in to any available part of the address space.
func allocStack(ctx context.Context, m *mm.MemoryManager, a *arch.Context64) (*arch.Stack, error) {
	ar, err := m.MapStack(ctx)
	if err != nil {
		return nil, err
	}
	return &arch.Stack{Arch: a, IO: m, Bottom: ar.End}, nil
}

const (
	// maxLoaderAttempts is the maximum number of attempts to try to load
	// an interpreter scripts, to prevent loops. 6 (initial + 5 changes) is
	// what the Linux kernel allows (fs/exec.c:search_binary_handler).
	maxLoaderAttempts = 6
)

// loadExecutable loads an executable that is pointed to by args.File. The
// caller is responsible for checking that the user can execute this file.
// If nil, the path args.Filename is resolved and loaded (check that the user
// can execute this file is done here in this case). If the executable is an
// interpreter script rather than an ELF, the binary of the corresponding
// interpreter will be loaded.
type executableResult struct {
	loaded          loadedELF
	arch            *arch.Context64
	file            *vfs.FileDescription
	argv            []string
	envv            []string
	execFD          *vfs.FileDescription
	credsFromBinary bool
}

func loadExecutable(ctx context.Context, args LoadArgs) (result executableResult, err error) {
	defer func() {
		if err != nil && result.execFD != nil {
			result.execFD.DecRef(ctx)
			result.execFD = nil
		}
	}()
	for i := 0; i < maxLoaderAttempts; i++ {
		if args.File == nil {
			args.File, err = openPath(ctx, args)
			if err != nil {
				// ENOENT is common for runtimes that try to exec many locations on PATH (e.g Python).
				// Don't log those errors to avoid spam.
				if !errors.Is(err, linuxerr.ENOENT) {
					ctx.Infof("Error opening %s: %v", args.Filename, err)
				}
				return result, err
			}
			// Ensure file is release in case the code loops or errors out.
			defer args.File.DecRef(ctx)
		} else {
			if err := checkIsRegularFile(ctx, args.File, args.Filename); err != nil {
				return result, err
			}
		}

		// Check the header. Is this an ELF or interpreter script?
		var hdr [256]uint8
		// N.B. We assume that reading from a regular file cannot block.
		n, readErr := args.File.ReadFull(ctx, usermem.BytesIOSequence(hdr[:]), 0)
		// Allow unexpected EOF, as a valid executable could be only three bytes
		// (e.g., #!a).
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			if readErr == io.EOF {
				readErr = linuxerr.ENOEXEC
			}
			return result, readErr
		}

		if args.BinaryFormats != nil {
			match, matchErr := args.BinaryFormats.Match(ctx, hdr[:], args.Filename, args.Argv, args.File)
			if matchErr != nil {
				return result, matchErr
			}
			if match != nil {
				if match.Interpreter == "" || (match.CredentialsFromBinary && !match.OpenBinary) {
					if match.InterpreterFile != nil {
						match.InterpreterFile.DecRef(ctx)
					}
					return result, linuxerr.EINVAL
				}
				if args.CloseOnExec {
					if match.InterpreterFile != nil {
						match.InterpreterFile.DecRef(ctx)
					}
					return result, linuxerr.ENOENT
				}
				if match.OpenBinary {
					if result.execFD != nil {
						if match.InterpreterFile != nil {
							match.InterpreterFile.DecRef(ctx)
						}
						return result, linuxerr.ENOEXEC
					}
					args.File.IncRef()
					result.execFD = args.File
					result.credsFromBinary = match.CredentialsFromBinary
				}
				args.Filename = match.Interpreter
				args.Argv = match.Argv
				if len(match.EnvAdd) != 0 {
					args.Envv, err = addInterpreterEnv(args.Envv, match.EnvAdd)
					if err != nil {
						if match.InterpreterFile != nil {
							match.InterpreterFile.DecRef(ctx)
						}
						return result, err
					}
				}
				if match.InterpreterFile != nil {
					file := match.InterpreterFile
					defer file.DecRef(ctx)
					args.File = file
				} else {
					args.File = nil
				}
				continue
			}
		}

		switch {
		case n >= int64(len(elfMagic)) && bytes.Equal(hdr[:len(elfMagic)], []byte(elfMagic)):
			loaded, ac, err := loadELF(ctx, args)
			if err != nil {
				ctx.Infof("Error loading ELF: %v", err)
				return result, err
			}
			// An ELF is always terminal. Hold on to file.
			args.File.IncRef()
			result.loaded = loaded
			result.arch = ac
			result.file = args.File
			result.argv = args.Argv
			result.envv = args.Envv
			return result, nil

		case n >= 2 && bytes.Equal(hdr[:2], []byte(interpreterScriptMagic)):
			if args.CloseOnExec {
				return result, linuxerr.ENOENT
			}
			args.Filename, args.Argv, err = parseInterpreterScript(ctx, args.Filename, args.File, args.Argv)
			if err != nil {
				ctx.Infof("Error loading interpreter script: %v", err)
				return result, err
			}
			// Refresh the traversal limit for the interpreter.
			*args.RemainingTraversals = linux.MaxSymlinkTraversals

		default:
			ctx.Infof("Unknown magic for %s: %v", args.Filename, hdr)
			return result, linuxerr.ENOEXEC
		}
		// Set to nil in case we loop on a Interpreter Script.
		args.File = nil
	}

	return result, linuxerr.ELOOP
}

// ImageInfo represents the information for the loaded image.
type ImageInfo struct {
	// The target operating system of the image.
	OS abi.OS
	// AMD64 context.
	Arch *arch.Context64
	// The base name of the binary.
	Name string
	// ExecFD is installed in the task FD table when exec commits.
	ExecFD *vfs.FileDescription
	// ExecFDValueAddr points at the AT_EXECFD value on the new user stack.
	ExecFDValueAddr hostarch.Addr
}

// Load loads args.File into a MemoryManager. If args.File is nil, the path
// args.Filename is resolved and loaded instead. Load also returns the new
// credentials for the task after execve and a bool indicating whether the
// task is executing with elevated privileges.
//
// If Load returns ErrSwitchFile it should be called again with the returned
// path and argv.
//
// Preconditions:
//   - The Task MemoryManager is empty.
//   - Load is called on the Task goroutine.
func Load(ctx context.Context, args LoadArgs, extraAuxv []arch.AuxEntry, vdso *VDSO) (ImageInfo, *auth.Credentials, bool, *syserr.Error) {
	// Load the executable itself.
	executable, err := loadExecutable(ctx, args)
	if err != nil {
		return ImageInfo{}, nil, false, syserr.NewDynamic(fmt.Sprintf("failed to load %s: %v", args.Filename, err), syserr.FromError(err).ToLinux())
	}
	loaded, ac, file, newArgv := executable.loaded, executable.arch, executable.file, executable.argv
	defer file.DecRef(ctx)
	defer func() {
		if executable.execFD != nil {
			executable.execFD.DecRef(ctx)
		}
	}()
	args.StartupTimeline.Reached("executable loaded")

	// Load the VDSO.
	vdsoAddr, err := loadVDSO(ctx, args.MemoryManager, vdso, loaded)
	if err != nil {
		return ImageInfo{}, nil, false, syserr.NewDynamic(fmt.Sprintf("error loading VDSO: %v", err), syserr.FromError(err).ToLinux())
	}
	args.StartupTimeline.Reached("VDSO mapped")

	// Setup the heap. brk starts at the next page after the end of the
	// executable. Userspace can assume that the remainder of the page after
	// loaded.end is available for its use.
	e, ok := loaded.end.RoundUp()
	if !ok {
		return ImageInfo{}, nil, false, syserr.NewDynamic(fmt.Sprintf("brk overflows: %#x", loaded.end), errno.ENOEXEC)
	}
	args.MemoryManager.BrkSetup(ctx, e)

	// Allocate our stack.
	stack, err := allocStack(ctx, args.MemoryManager, ac)
	if err != nil {
		return ImageInfo{}, nil, false, syserr.NewDynamic(fmt.Sprintf("Failed to allocate stack: %v", err), syserr.FromError(err).ToLinux())
	}
	args.StartupTimeline.Reached("stack allocated")

	// Push the original filename to the stack, for AT_EXECFN.
	if _, err := stack.PushNullTerminatedByteSlice([]byte(args.Filename)); err != nil {
		return ImageInfo{}, nil, false, syserr.NewDynamic(fmt.Sprintf("Failed to push exec filename: %v", err), syserr.FromError(err).ToLinux())
	}
	execfn := stack.Bottom

	// Push 16 random bytes on the stack which AT_RANDOM will point to.
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ImageInfo{}, nil, false, syserr.NewDynamic(fmt.Sprintf("Failed to read random bytes: %v", err), syserr.FromError(err).ToLinux())
	}
	if _, err = stack.PushNullTerminatedByteSlice(b[:]); err != nil {
		return ImageInfo{}, nil, false, syserr.NewDynamic(fmt.Sprintf("Failed to push random bytes: %v", err), syserr.FromError(err).ToLinux())
	}
	random := stack.Bottom

	// Push the platform string which AT_PLATFORM will point to.
	if _, err = stack.PushNullTerminatedByteSlice([]byte(loaded.arch.Platform())); err != nil {
		return ImageInfo{}, nil, false, syserr.NewDynamic(fmt.Sprintf("Failed to push platform string: %v", err), syserr.FromError(err).ToLinux())
	}
	platform := stack.Bottom

	credsFile := file
	if executable.credsFromBinary {
		credsFile = executable.execFD
	}
	filePrivs, err := credsFile.GetFilePrivileges(ctx)
	if err != nil {
		return ImageInfo{}, nil, false, syserr.NewDynamic(fmt.Sprintf("failed to read file privileges of %s: %v", args.Filename, err), syserr.FromError(err).ToLinux())
	}
	c, secureExec, err := auth.ComputeCredsForExec(auth.CredentialsFromContext(ctx), filePrivs, credsFile.MappedName(ctx),
		args.NoNewPrivs, args.StopPrivGain, args.AllowSUID)
	if err != nil {
		return ImageInfo{}, nil, false, syserr.NewDynamic(fmt.Sprintf("failed to update creds with file privileges: %v", err), syserr.FromError(err).ToLinux())
	}
	secureExecInt := 0
	if secureExec {
		secureExecInt = 1
	}

	// Add generic auxv entries.
	auxv := append(loaded.auxv, arch.Auxv{
		arch.AuxEntry{linux.AT_UID, hostarch.Addr(c.RealKUID.In(c.UserNamespace).OrOverflow())},
		arch.AuxEntry{linux.AT_EUID, hostarch.Addr(c.EffectiveKUID.In(c.UserNamespace).OrOverflow())},
		arch.AuxEntry{linux.AT_GID, hostarch.Addr(c.RealKGID.In(c.UserNamespace).OrOverflow())},
		arch.AuxEntry{linux.AT_EGID, hostarch.Addr(c.EffectiveKGID.In(c.UserNamespace).OrOverflow())},
		arch.AuxEntry{linux.AT_SECURE, hostarch.Addr(secureExecInt)},
		arch.AuxEntry{linux.AT_CLKTCK, linux.CLOCKS_PER_SEC},
		arch.AuxEntry{linux.AT_EXECFN, execfn},
		arch.AuxEntry{linux.AT_RANDOM, random},
		arch.AuxEntry{linux.AT_PLATFORM, platform},
		arch.AuxEntry{linux.AT_PAGESZ, hostarch.PageSize},
		arch.AuxEntry{linux.AT_SYSINFO_EHDR, vdsoAddr},
		arch.AuxEntry{linux.AT_HWCAP, hostarch.Addr(args.Features.AllowedHWCap1())},
		arch.AuxEntry{linux.AT_HWCAP2, hostarch.Addr(args.Features.AllowedHWCap2())},
	}...)
	if executable.execFD != nil {
		auxv = append(auxv, arch.AuxEntry{Key: linux.AT_EXECFD})
	}

	sl, err := stack.Load(newArgv, executable.envv, auxv)
	if err != nil {
		return ImageInfo{}, nil, false, syserr.NewDynamic(fmt.Sprintf("Failed to load stack: %v", err), syserr.FromError(err).ToLinux())
	}
	args.StartupTimeline.Reached("stack contents loaded")

	m := args.MemoryManager
	m.SetArgvStart(sl.ArgvStart)
	m.SetArgvEnd(sl.ArgvEnd)
	m.SetEnvvStart(sl.EnvvStart)
	m.SetEnvvEnd(sl.EnvvEnd)
	m.SetAuxv(auxv)
	m.SetExecutable(ctx, file)
	m.SetVDSOSigReturn(uint64(vdsoAddr) + vdsoSigreturnOffset - vdsoPrelink)

	ac.SetIP(uintptr(loaded.entry))
	ac.SetStack(uintptr(stack.Bottom))

	name := path.Base(args.Filename)
	if len(name) > linux.TASK_COMM_LEN-1 {
		name = name[:linux.TASK_COMM_LEN-1]
	}

	info := ImageInfo{
		OS:   loaded.os,
		Arch: ac,
		Name: name,
	}
	if executable.execFD != nil {
		info.ExecFD = executable.execFD
		info.ExecFDValueAddr = sl.AuxvStart + hostarch.Addr(uint(len(auxv)-1)*2*ac.Width()+ac.Width())
		executable.execFD = nil
	}
	return info, c, secureExec, nil
}
