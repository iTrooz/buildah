//go:build linux

package chroot

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/moby/sys/capability"
	"github.com/opencontainers/runc/libcontainer/apparmor"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"go.podman.io/storage/pkg/unshare"
	"golang.org/x/sys/unix"
)

var (
	rlimitsMap = map[string]int{
		"RLIMIT_AS":         unix.RLIMIT_AS,
		"RLIMIT_CORE":       unix.RLIMIT_CORE,
		"RLIMIT_CPU":        unix.RLIMIT_CPU,
		"RLIMIT_DATA":       unix.RLIMIT_DATA,
		"RLIMIT_FSIZE":      unix.RLIMIT_FSIZE,
		"RLIMIT_LOCKS":      unix.RLIMIT_LOCKS,
		"RLIMIT_MEMLOCK":    unix.RLIMIT_MEMLOCK,
		"RLIMIT_MSGQUEUE":   unix.RLIMIT_MSGQUEUE,
		"RLIMIT_NICE":       unix.RLIMIT_NICE,
		"RLIMIT_NOFILE":     unix.RLIMIT_NOFILE,
		"RLIMIT_NPROC":      unix.RLIMIT_NPROC,
		"RLIMIT_RSS":        unix.RLIMIT_RSS,
		"RLIMIT_RTPRIO":     unix.RLIMIT_RTPRIO,
		"RLIMIT_RTTIME":     unix.RLIMIT_RTTIME,
		"RLIMIT_SIGPENDING": unix.RLIMIT_SIGPENDING,
		"RLIMIT_STACK":      unix.RLIMIT_STACK,
	}
	rlimitsReverseMap = map[int]string{}
	mountFlagMap      = map[int]string{
		unix.MS_ACTIVE:       "MS_ACTIVE",
		unix.MS_BIND:         "MS_BIND",
		unix.MS_BORN:         "MS_BORN",
		unix.MS_DIRSYNC:      "MS_DIRSYNC",
		unix.MS_KERNMOUNT:    "MS_KERNMOUNT",
		unix.MS_LAZYTIME:     "MS_LAZYTIME",
		unix.MS_MANDLOCK:     "MS_MANDLOCK",
		unix.MS_MOVE:         "MS_MOVE",
		unix.MS_NOATIME:      "MS_NOATIME",
		unix.MS_NODEV:        "MS_NODEV",
		unix.MS_NODIRATIME:   "MS_NODIRATIME",
		unix.MS_NOEXEC:       "MS_NOEXEC",
		unix.MS_NOREMOTELOCK: "MS_NOREMOTELOCK",
		unix.MS_NOSEC:        "MS_NOSEC",
		unix.MS_NOSUID:       "MS_NOSUID",
		unix.MS_NOSYMFOLLOW:  "MS_NOSYMFOLLOW",
		unix.MS_NOUSER:       "MS_NOUSER",
		unix.MS_POSIXACL:     "MS_POSIXACL",
		unix.MS_PRIVATE:      "MS_PRIVATE",
		unix.MS_RDONLY:       "MS_RDONLY",
		unix.MS_REC:          "MS_REC",
		unix.MS_RELATIME:     "MS_RELATIME",
		unix.MS_REMOUNT:      "MS_REMOUNT",
		unix.MS_SHARED:       "MS_SHARED",
		unix.MS_SILENT:       "MS_SILENT",
		unix.MS_SLAVE:        "MS_SLAVE",
		unix.MS_STRICTATIME:  "MS_STRICTATIME",
		unix.MS_SUBMOUNT:     "MS_SUBMOUNT",
		unix.MS_SYNCHRONOUS:  "MS_SYNCHRONOUS",
		unix.MS_UNBINDABLE:   "MS_UNBINDABLE",
	}
	statFlagMap = map[int]string{
		unix.ST_MANDLOCK:    "ST_MANDLOCK",
		unix.ST_NOATIME:     "ST_NOATIME",
		unix.ST_NODEV:       "ST_NODEV",
		unix.ST_NODIRATIME:  "ST_NODIRATIME",
		unix.ST_NOEXEC:      "ST_NOEXEC",
		unix.ST_NOSUID:      "ST_NOSUID",
		unix.ST_RDONLY:      "ST_RDONLY",
		unix.ST_RELATIME:    "ST_RELATIME",
		unix.ST_SYNCHRONOUS: "ST_SYNCHRONOUS",
	}
)

func mountFlagNames(flags uintptr) []string {
	var names []string
	for flag, name := range mountFlagMap {
		if int(flags)&flag == flag {
			names = append(names, name)
			flags = flags &^ (uintptr(flag))
		}
	}
	if flags != 0 { // got some unknown leftovers
		names = append(names, fmt.Sprintf("%#x", flags))
	}
	slices.Sort(names)
	return names
}

func statFlagNames(flags uintptr) []string {
	var names []string
	flags = flags & ^uintptr(0x20) // mask off ST_VALID
	for flag, name := range statFlagMap {
		if int(flags)&flag == flag {
			names = append(names, name)
			flags = flags &^ (uintptr(flag))
		}
	}
	if flags != 0 { // got some unknown leftovers
		names = append(names, fmt.Sprintf("%#x", flags))
	}
	slices.Sort(names)
	return names
}

type runUsingChrootSubprocOptions struct {
	Spec        *specs.Spec
	BundlePath  string
	NoPivot     bool
	SkipUnshare bool
	UIDMappings []syscall.SysProcIDMap
	GIDMappings []syscall.SysProcIDMap
}

func setPlatformUnshareOptions(spec *specs.Spec, cmd *unshare.Cmd) error {
	// If we have configured ID mappings, set them here so that they can apply to the child.
	hostUidmap, hostGidmap, err := unshare.GetHostIDMappings("")
	if err != nil {
		return err
	}
	uidmap, gidmap := spec.Linux.UIDMappings, spec.Linux.GIDMappings
	if len(uidmap) == 0 {
		// No UID mappings are configured for the container.  Borrow our parent's mappings.
		uidmap = slices.Clone(hostUidmap)
		for i := range uidmap {
			uidmap[i].HostID = uidmap[i].ContainerID
		}
	}
	if len(gidmap) == 0 {
		// No GID mappings are configured for the container.  Borrow our parent's mappings.
		gidmap = slices.Clone(hostGidmap)
		for i := range gidmap {
			gidmap[i].HostID = gidmap[i].ContainerID
		}
	}

	shouldSkipUnshare := os.Getenv("_CONTAINERS_UNSHARE_MODE") == "never"
	// POC: always skip unshare - set flags to 0
	cmd.UnshareFlags = 0
	requestedUserNS := false
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == specs.UserNamespace {
			requestedUserNS = true
		}
	}
	if len(spec.Linux.UIDMappings) > 0 || len(spec.Linux.GIDMappings) > 0 || requestedUserNS {
		fmt.Fprintf(os.Stderr, "DEBUG: setPlatformUnshareOptions: Adding CLONE_NEWUSER to UnshareFlags, UIDMappings=%d GIDMappings=%d requestedUserNS=%v\n", len(spec.Linux.UIDMappings), len(spec.Linux.GIDMappings), requestedUserNS)
		if !shouldSkipUnshare {
			cmd.UnshareFlags = cmd.UnshareFlags | syscall.CLONE_NEWUSER
			cmd.UidMappings = uidmap
			cmd.GidMappings = gidmap
			cmd.GidMappingsEnableSetgroups = true
		}
	}
	cmd.OOMScoreAdj = spec.Process.OOMScoreAdj
	return nil
}

func setPlatformUnshareOptionsForSubproc(spec *specs.Spec, cmd *unshare.Cmd, skipUnshare bool) error {
	shouldSkipUnshare := skipUnshare
	if shouldSkipUnshare {
		cmd.UnshareFlags = 0
	} else {
		cmd.UnshareFlags = syscall.CLONE_NEWUTS | syscall.CLONE_NEWNS
	}
	requestedUserNS := false
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == specs.UserNamespace {
			requestedUserNS = true
		}
	}
	if len(spec.Linux.UIDMappings) > 0 || len(spec.Linux.GIDMappings) > 0 || requestedUserNS {
		fmt.Fprintf(os.Stderr, "DEBUG: setPlatformUnshareOptionsForSubproc: Adding CLONE_NEWUSER to UnshareFlags, UIDMappings=%d GIDMappings=%d requestedUserNS=%v\n", len(spec.Linux.UIDMappings), len(spec.Linux.GIDMappings), requestedUserNS)
		if !shouldSkipUnshare {
			cmd.UnshareFlags = cmd.UnshareFlags | syscall.CLONE_NEWUSER
			cmd.UidMappings = spec.Linux.UIDMappings
			cmd.GidMappings = spec.Linux.GIDMappings
			cmd.GidMappingsEnableSetgroups = true
		}
	}
	cmd.OOMScoreAdj = spec.Process.OOMScoreAdj
	return nil
}

func setContainerHostname(name string) {
	if err := unix.Sethostname([]byte(name)); err != nil {
		logrus.Debugf("failed to set hostname %q for process: %v", name, err)
	}
}

// logNamespaceDiagnostics knows which namespaces we want to create.
// Output debug messages when that differs from what we're being asked to do.
func logNamespaceDiagnostics(spec *specs.Spec) {
	sawMountNS := false
	sawUTSNS := false
	for _, ns := range spec.Linux.Namespaces {
		switch ns.Type {
		case specs.CgroupNamespace:
			if ns.Path != "" {
				logrus.Debugf("unable to join cgroup namespace, sorry about that")
			} else {
				logrus.Debugf("unable to create cgroup namespace, sorry about that")
			}
		case specs.IPCNamespace:
			if ns.Path != "" {
				logrus.Debugf("unable to join IPC namespace, sorry about that")
			} else {
				logrus.Debugf("unable to create IPC namespace, sorry about that")
			}
		case specs.MountNamespace:
			if ns.Path != "" {
				logrus.Debugf("unable to join mount namespace %q, creating a new one", ns.Path)
			}
			sawMountNS = true
		case specs.NetworkNamespace:
			if ns.Path != "" {
				logrus.Debugf("unable to join network namespace, sorry about that")
			} else {
				logrus.Debugf("unable to create network namespace, sorry about that")
			}
		case specs.PIDNamespace:
			if ns.Path != "" {
				logrus.Debugf("unable to join PID namespace, sorry about that")
			} else {
				logrus.Debugf("unable to create PID namespace, sorry about that")
			}
		case specs.UserNamespace:
			if ns.Path != "" {
				logrus.Debugf("unable to join user namespace, sorry about that")
			}
		case specs.UTSNamespace:
			if ns.Path != "" {
				logrus.Debugf("unable to join UTS namespace %q, creating a new one", ns.Path)
			}
			sawUTSNS = true
		}
	}
	if !sawMountNS {
		logrus.Debugf("mount namespace not requested, but creating a new one anyway")
	}
	if !sawUTSNS {
		logrus.Debugf("UTS namespace not requested, but creating a new one anyway")
	}
}

// setApparmorProfile sets the apparmor profile for ourselves, and hopefully any child processes that we'll start.
func setApparmorProfile(spec *specs.Spec) error {
	if !apparmor.IsEnabled() || spec.Process.ApparmorProfile == "" {
		return nil
	}
	if err := apparmor.ApplyProfile(spec.Process.ApparmorProfile); err != nil {
		return fmt.Errorf("setting apparmor profile to %q: %w", spec.Process.ApparmorProfile, err)
	}
	return nil
}

// setCapabilities sets capabilities for ourselves, to be more or less inherited by any processes that we'll start.
func setCapabilities(spec *specs.Spec, keepCaps ...string) error {
	currentCaps, err := capability.NewPid2(0)
	if err != nil {
		return fmt.Errorf("reading capabilities of current process: %w", err)
	}
	if err := currentCaps.Load(); err != nil {
		return fmt.Errorf("loading capabilities: %w", err)
	}
	caps, err := capability.NewPid2(0)
	if err != nil {
		return fmt.Errorf("reading capabilities of current process: %w", err)
	}
	capMap := map[capability.CapType][]string{
		capability.BOUNDING:    spec.Process.Capabilities.Bounding,
		capability.EFFECTIVE:   spec.Process.Capabilities.Effective,
		capability.INHERITABLE: {},
		capability.PERMITTED:   spec.Process.Capabilities.Permitted,
		capability.AMBIENT:     {},
	}
	knownCaps := capability.ListKnown()
	noCap := capability.Cap(-1)
	for capType, capList := range capMap {
		for _, capSpec := range capList {
			capToSet := noCap
			for _, c := range knownCaps {
				if strings.EqualFold("CAP_"+c.String(), capSpec) {
					capToSet = c
					break
				}
			}
			if capToSet == noCap {
				return fmt.Errorf("mapping capability %q to a number", capSpec)
			}
			caps.Set(capType, capToSet)
		}
		for _, capSpec := range keepCaps {
			capToSet := noCap
			for _, c := range knownCaps {
				if strings.EqualFold("CAP_"+c.String(), capSpec) {
					capToSet = c
					break
				}
			}
			if capToSet == noCap {
				return fmt.Errorf("mapping capability %q to a number", capSpec)
			}
			if currentCaps.Get(capType, capToSet) {
				caps.Set(capType, capToSet)
			}
		}
	}
	if err = caps.Apply(capability.CAPS | capability.BOUNDS | capability.AMBS); err != nil {
		return fmt.Errorf("setting capabilities: %w", err)
	}
	return nil
}

func makeRlimit(limit specs.POSIXRlimit) unix.Rlimit {
	return unix.Rlimit{Cur: limit.Soft, Max: limit.Hard}
}

func createPlatformContainer(options runUsingChrootExecSubprocOptions) error {
	if options.NoPivot {
		return errors.New("not using pivot_root()")
	}
	// borrowing a technique from runc, who credit the LXC maintainers for this
	// open descriptors for the old and new root directories so that we can use fchdir()
	oldRootFd, err := unix.Open("/", unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("opening host root directory: %w", err)
	}
	defer func() {
		if err := unix.Close(oldRootFd); err != nil {
			logrus.Warnf("closing host root directory: %v", err)
		}
	}()
	newRootFd, err := unix.Open(options.Spec.Root.Path, unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("opening container root directory: %w", err)
	}
	defer func() {
		if err := unix.Close(newRootFd); err != nil {
			logrus.Warnf("closing container root directory: %v", err)
		}
	}()
	// change to the new root directory
	if err := unix.Fchdir(newRootFd); err != nil {
		return fmt.Errorf("changing to container root directory: %w", err)
	}
	// this makes the current directory the root directory. not actually
	// sure what happens to the other one
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	// go back and clean up the old one
	if err := unix.Fchdir(oldRootFd); err != nil {
		return fmt.Errorf("changing to host root directory: %w", err)
	}
	// make sure we only unmount things under this tree
	if err := unix.Mount(".", ".", "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("tweaking mount flags on host root directory before unmounting from mount namespace: %w", err)
	}
	// detach this (unnamed?) old directory
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("unmounting host root directory in mount namespace: %w", err)
	}
	// go back to a named root directory
	if err := unix.Fchdir(newRootFd); err != nil {
		return fmt.Errorf("changing to container root directory at last: %w", err)
	}
	logrus.Debugf("pivot_root()ed into %q", options.Spec.Root.Path)
	return nil
}

func mountFlagsForFSFlags(fsFlags uintptr) uintptr {
	var mountFlags uintptr
	for _, mapping := range []struct {
		fsFlag    uintptr
		mountFlag uintptr
	}{
		{unix.ST_MANDLOCK, unix.MS_MANDLOCK},
		{unix.ST_NOATIME, unix.MS_NOATIME},
		{unix.ST_NODEV, unix.MS_NODEV},
		{unix.ST_NODIRATIME, unix.MS_NODIRATIME},
		{unix.ST_NOEXEC, unix.MS_NOEXEC},
		{unix.ST_NOSUID, unix.MS_NOSUID},
		{unix.ST_RDONLY, unix.MS_RDONLY},
		{unix.ST_RELATIME, unix.MS_RELATIME},
		{unix.ST_SYNCHRONOUS, unix.MS_SYNCHRONOUS},
	} {
		if fsFlags&mapping.fsFlag == mapping.fsFlag {
			mountFlags |= mapping.mountFlag
		}
	}
	return mountFlags
}

func makeReadOnly(mntpoint string, flags uintptr) error {
	var fs unix.Statfs_t
	// Make sure it's read-only.
	if err := unix.Statfs(mntpoint, &fs); err != nil {
		return fmt.Errorf("checking if directory %q was bound read-only: %w", mntpoint, err)
	}
	if fs.Flags&unix.ST_RDONLY == 0 {
		// All callers currently pass MS_RDONLY in "flags", but in case they stop doing
		// that at some point in the future...
		if err := unix.Mount(mntpoint, mntpoint, "bind", flags|unix.MS_RDONLY|unix.MS_REMOUNT|unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("remounting %s in mount namespace read-only: %w", mntpoint, err)
		}
	}
	return nil
}

// setupChrootBindMounts actually bind mounts things under the rootfs, and returns a
// callback that will clean up its work.
func setupChrootBindMounts(spec *specs.Spec, bundlePath string) (undoBinds func() error, err error) {
	undoBinds = func() error {
		if err2 := unix.Unmount(spec.Root.Path, unix.MNT_DETACH); err2 != nil {
			retries := 0
			for (err2 == unix.EBUSY || err2 == unix.EAGAIN) && retries < 50 {
				time.Sleep(50 * time.Millisecond)
				err2 = unix.Unmount(spec.Root.Path, unix.MNT_DETACH)
				retries++
			}
			if err2 != nil {
				logrus.Warnf("pkg/chroot: error unmounting %q (retried %d times): %v", spec.Root.Path, retries, err2)
				if err == nil {
					err = err2
				}
			}
		}
		return err
	}

	// SKIP all bind mounts for unprivileged mode
	fmt.Fprintf(os.Stderr, "DEBUG: setupChrootBindMounts: skipping all mounts (unprivileged mode)\n")
	return undoBinds, nil
}

	// setPdeathsig sets a parent-death signal for the process
func setPdeathsig(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
}
