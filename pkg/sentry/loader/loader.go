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

	// ExecFD, if non-nil, is installed into the task's FD table at exec
	// commit (lowest free FD, no O_CLOEXEC) and reported to the new image
	// via AT_EXECFD. Set by binfmt_misc rewrites with the O/C flags
	// (Linux fs/binfmt_misc.c: bprm->executable). (rosetta 补丁 0020)
	ExecFD *vfs.FileDescription

	// CredsFromBinary indicates that exec credentials are computed from
	// the binary (ExecFD) instead of the interpreter file (binfmt_misc
	// C flag; Linux fs/exec.c: bprm->execfd_creds). (rosetta 补丁 0020)
	CredsFromBinary bool

	// synthesize, if non-nil, short-circuits loading: the matched
	// binfmt_misc entry synthesizes the new image directly instead of
	// executing an interpreter file. Installed only by kernel-integrated
	// entries; guest-registered entries always execute their interpreter.
	// (rosetta 补丁 0020)
	synthesize SynthesizeFunc

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

// SynthesizeFunc builds the new process image for a binfmt_misc entry
// that is handled directly by its registrar instead of by executing an
// interpreter file (rosetta 补丁 0020). It is called from Load with the
// working LoadArgs (MemoryManager is already set; Filename/Argv are the
// original, unrewritten values) and the open target file, and returns the
// image, post-exec credentials and secure-exec flag exactly as Load would.
type SynthesizeFunc func(ctx context.Context, args LoadArgs, file *vfs.FileDescription) (ImageInfo, *auth.Credentials, bool, *syserr.Error)

// BinfmtMiscMatch describes a binfmt_misc interpreter rewrite.
// (rosetta 补丁 0020; semantics: Linux fs/binfmt_misc.c:load_misc_binary)
type BinfmtMiscMatch struct {
	// Interpreter is the interpreter path (the rewritten load target).
	Interpreter string

	// InterpFile, if non-nil, is loaded instead of opening Interpreter
	// (F flag: file pinned at registration time). Ownership is
	// transferred to the loader.
	InterpFile *vfs.FileDescription

	// Argv is the rewritten argument vector (P/O flag semantics applied).
	Argv []string

	// ExecFD, if non-nil (O/C flags), is installed into the task's FD
	// table at exec commit (lowest free FD, no O_CLOEXEC) and reported
	// to the new image via AT_EXECFD. Ownership is transferred to the
	// loader.
	ExecFD *vfs.FileDescription

	// CredsFromBinary indicates that exec credentials are computed from
	// the binary (ExecFD) instead of the interpreter (C flag).
	CredsFromBinary bool

	// Synthesize, if non-nil, marks the entry as registrar-handled: the
	// image is synthesized directly (no interpreter execution, no argv
	// rewrite). Only kernel-integrated entries may set this; matches from
	// guest-registered entries always leave it nil.
	Synthesize SynthesizeFunc
}

// BinfmtMiscHook matches a file against the binfmt_misc registry. It is
// installed by the binfmt_misc subsystem at kernel setup; nil means no
// binfmt_misc support. (rosetta 补丁 0020)
//
// header holds the bytes read from the head of the file being loaded (up
// to 256, Linux BINPRM_BUF_SIZE); filename is the current-level path
// (Linux bprm->interp); argv is the current argument vector; file is the
// open executable. A nil match with nil error means "no registered entry
// matched" (loading continues to the next format); a non-nil error aborts
// the exec (Linux: any handler error other than -ENOEXEC aborts).
var BinfmtMiscHook func(ctx context.Context, header []byte, filename string, argv []string, file *vfs.FileDescription) (*BinfmtMiscMatch, error)

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

// loadExecutable loads an executable that is pointed to by out.File. The
// caller is responsible for checking that the user can execute this file.
// If nil, the path out.Filename is resolved and loaded (check that the user
// can execute this file is done here in this case). If the executable is an
// interpreter script or matches a binfmt_misc entry, the binary of the
// corresponding interpreter will be loaded instead. (rosetta 补丁 0020:
// the working LoadArgs is returned on success; it carries the rewritten
// argv and any binfmt_misc side effects (ExecFD/CredsFromBinary). The
// caller's own copy keeps the original Filename for AT_EXECFN/comm,
// matching Linux's bprm->filename.)
//
// It returns:
//   - loadedELF, description of the loaded binary
//   - arch.Context64 matching the binary arch
//   - fs.Dirent of the binary file
//   - Possibly updated LoadArgs
func loadExecutable(ctx context.Context, args LoadArgs) (loaded loadedELF, ac *arch.Context64, file *vfs.FileDescription, out LoadArgs, err error) {
	out = args
	defer func() {
		if err != nil && out.ExecFD != nil {
			out.ExecFD.DecRef(ctx)
			out.ExecFD = nil
		}
	}()
	for i := 0; i < maxLoaderAttempts; i++ {
		if out.File == nil {
			out.File, err = openPath(ctx, out)
			if err != nil {
				// ENOENT is common for runtimes that try to exec many locations on PATH (e.g Python).
				// Don't log those errors to avoid spam.
				if !errors.Is(err, linuxerr.ENOENT) {
					ctx.Infof("Error opening %s: %v", out.Filename, err)
				}
				return loadedELF{}, nil, nil, LoadArgs{}, err
			}
			// Ensure file is release in case the code loops or errors out.
			defer out.File.DecRef(ctx)
		} else {
			if err = checkIsRegularFile(ctx, out.File, out.Filename); err != nil {
				return loadedELF{}, nil, nil, LoadArgs{}, err
			}
		}

		// Check the header: binfmt_misc match, ELF, or interpreter script?
		// Linux reads BINPRM_BUF_SIZE (256) bytes per rewrite level
		// (fs/exec.c:prepare_binprm); binfmt_misc magic matching needs the
		// same window. (rosetta 补丁 0020)
		var hdr [256]uint8
		// N.B. We assume that reading from a regular file cannot block.
		var n int64
		n, err = out.File.ReadFull(ctx, usermem.BytesIOSequence(hdr[:]), 0)
		// Allow unexpected EOF, as a valid executable could be only three bytes
		// (e.g., #!a).
		if err != nil && err != io.ErrUnexpectedEOF {
			if err == io.EOF {
				err = linuxerr.ENOEXEC
			}
			return loadedELF{}, nil, nil, LoadArgs{}, err
		}
		head := hdr[:n]

		// binfmt_misc is tried first: Linux's insert_binfmt() inserts it
		// at the head of the formats list. A match rewrites the load
		// target to the registered interpreter and loops. (rosetta 补丁 0020)
		if BinfmtMiscHook != nil {
			var match *BinfmtMiscMatch
			match, err = BinfmtMiscHook(ctx, head, out.Filename, out.Argv, out.File)
			if err != nil {
				return loadedELF{}, nil, nil, LoadArgs{}, err
			}
			if match != nil {
				if out.CloseOnExec {
					// Linux fs/binfmt_misc.c:load_misc_binary() fails
					// with ENOENT when the binary's path becomes
					// inaccessible after exec.
					return loadedELF{}, nil, nil, LoadArgs{}, linuxerr.ENOENT
				}
				if match.Synthesize != nil {
					// Registrar-handled entry: the image is synthesized
					// directly from the original file/argv (no rewrite,
					// no interpreter execution). The target file stays
					// open for the synthesizer (credentials, exe link).
					out.synthesize = match.Synthesize
					out.File.IncRef()
					return loadedELF{}, nil, out.File, out, nil
				}
				out.Filename = match.Interpreter
				out.Argv = match.Argv
				if match.ExecFD != nil {
					if out.ExecFD != nil {
						// Linux exec_binprm(): a second execfd level
						// (bprm->executable already set) is a hard
						// ENOEXEC.
						match.ExecFD.DecRef(ctx)
						return loadedELF{}, nil, nil, LoadArgs{}, linuxerr.ENOEXEC
					}
					out.ExecFD = match.ExecFD
				}
				if match.CredsFromBinary {
					// bprm->execfd_creds is only ever set, never cleared,
					// across rewrite levels.
					out.CredsFromBinary = true
				}
				if match.InterpFile != nil {
					defer match.InterpFile.DecRef(ctx)
					out.File = match.InterpFile
				} else {
					out.File = nil
				}
				// Refresh the traversal limit for the interpreter.
				*out.RemainingTraversals = linux.MaxSymlinkTraversals
				continue
			}
		}

		switch {
		case n >= int64(len(elfMagic)) && bytes.Equal(head[:len(elfMagic)], []byte(elfMagic)):
			loaded, ac, err := loadELF(ctx, out)
			if err != nil {
				ctx.Infof("Error loading ELF: %v", err)
				return loadedELF{}, nil, nil, LoadArgs{}, err
			}
			// An ELF is always terminal. Hold on to file.
			out.File.IncRef()
			return loaded, ac, out.File, out, err

		case n >= 2 && bytes.Equal(head[:2], []byte(interpreterScriptMagic)):
			if out.CloseOnExec {
				return loadedELF{}, nil, nil, LoadArgs{}, linuxerr.ENOENT
			}
			out.Filename, out.Argv, err = parseInterpreterScript(ctx, out.Filename, out.File, out.Argv)
			if err != nil {
				ctx.Infof("Error loading interpreter script: %v", err)
				return loadedELF{}, nil, nil, LoadArgs{}, err
			}
			// Refresh the traversal limit for the interpreter.
			*out.RemainingTraversals = linux.MaxSymlinkTraversals

		default:
			ctx.Infof("Unknown magic: %v", head)
			return loadedELF{}, nil, nil, LoadArgs{}, linuxerr.ENOEXEC
		}
		// Set to nil in case we loop on a Interpreter Script.
		out.File = nil
	}

	return loadedELF{}, nil, nil, LoadArgs{}, linuxerr.ELOOP
}

// ImageInfo represents the information for the loaded image.
type ImageInfo struct {
	// The target operating system of the image.
	OS abi.OS
	// AMD64 context.
	Arch *arch.Context64
	// The base name of the binary.
	Name string

	// ExecFD, if non-nil, is installed into the task's FD table at exec
	// commit; the FD number is patched into the auxv entry at
	// ExecFDValueAddr (binfmt_misc O/C flags). Ownership is transferred
	// to the caller. (rosetta 补丁 0020)
	ExecFD *vfs.FileDescription
	// ExecFDValueAddr is the guest address of the AT_EXECFD auxv value
	// to patch at exec commit.
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
	loaded, ac, file, loadOut, err := loadExecutable(ctx, args)
	if err != nil {
		return ImageInfo{}, nil, false, syserr.NewDynamic(fmt.Sprintf("failed to load %s: %v", args.Filename, err), syserr.FromError(err).ToLinux())
	}
	defer file.DecRef(ctx)
	// A registrar-handled binfmt_misc entry synthesizes the image
	// directly, short-circuiting the rest of Load. (rosetta 补丁 0020)
	if loadOut.synthesize != nil {
		return loadOut.synthesize(ctx, loadOut, file)
	}
	newArgv := loadOut.Argv
	// A binfmt_misc rewrite with O/C flags hands us the binary to install
	// at exec commit; on any failure below it must be released.
	// (rosetta 补丁 0020)
	execFD := loadOut.ExecFD
	defer func() {
		if execFD != nil {
			execFD.DecRef(ctx)
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

	// binfmt_misc C flag: compute credentials from the binary instead of
	// the interpreter (Linux fs/exec.c: bprm->execfd_creds selects
	// bprm->executable). (rosetta 补丁 0020)
	credsFile := file
	if loadOut.CredsFromBinary && loadOut.ExecFD != nil {
		credsFile = loadOut.ExecFD
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
		arch.AuxEntry{linux.AT_PAGESZ, hostarch.PageSize},
		arch.AuxEntry{linux.AT_SYSINFO_EHDR, vdsoAddr},
		arch.AuxEntry{linux.AT_HWCAP, hostarch.Addr(args.Features.AllowedHWCap1())},
		arch.AuxEntry{linux.AT_HWCAP2, hostarch.Addr(args.Features.AllowedHWCap2())},
	}...)

	// binfmt_misc O flag: report the binary's FD (installed at exec
	// commit) via AT_EXECFD; the value is patched in place once the FD
	// number is known (Linux fs/binfmt_elf.c: NEW_AUX_ENT(AT_EXECFD,
	// bprm->execfd)). (rosetta 补丁 0020)
	execFDEntry := -1
	if loadOut.ExecFD != nil {
		auxv = append(auxv, arch.AuxEntry{linux.AT_EXECFD, 0})
		execFDEntry = len(auxv) - 1
	}

	sl, err := stack.Load(newArgv, args.Envv, auxv)
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
	if execFDEntry >= 0 {
		// Auxv entries are pairs of hostarch.Addr values; the FD number
		// goes into the value slot of the AT_EXECFD entry.
		info.ExecFD = execFD
		info.ExecFDValueAddr = sl.AuxvStart + hostarch.Addr(uint(execFDEntry)*2*ac.Width()+ac.Width())
		execFD = nil // ownership transferred to info
	}
	return info, c, secureExec, nil
}
