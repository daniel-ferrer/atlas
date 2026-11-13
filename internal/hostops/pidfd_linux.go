//go:build linux

package hostops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/daniel-ferrer/atlas/internal/collect"
	ps "github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/unix"
)

type pidHandle struct {
	fd  int
	pid int32
}

func (Real) OpenProcess(ctx context.Context, pid int32) (Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		return nil, err
	}
	return &pidHandle{fd: fd, pid: pid}, nil
}
func (p *pidHandle) Close() error                    { return unix.Close(p.fd) }
func (p *pidHandle) Signal(sig syscall.Signal) error { return unix.PidfdSendSignal(p.fd, sig, nil, 0) }
func (p *pidHandle) Identity(ctx context.Context) (Identity, error) {
	process, err := ps.NewProcessWithContext(ctx, p.pid)
	if err != nil {
		return Identity{}, err
	}
	user, command, created, err := collect.ProcessIdentity(ctx, process)
	if err != nil {
		return Identity{}, err
	}
	uids, err := process.UidsWithContext(ctx)
	if err != nil || len(uids) == 0 || user == "" || command == "" {
		return Identity{}, errors.New("process identity unavailable")
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", p.pid))
	if err != nil {
		return Identity{}, err
	}
	flags, err := StatFlags(string(stat))
	if err != nil {
		return Identity{}, err
	}
	cg, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", p.pid))
	if err != nil {
		return Identity{}, err
	}
	// Failure to traverse Atlas's ancestry refuses the kill, rather than assuming
	// an unreadable parent is safe.
	ancestor := false
	seen := map[int32]bool{}
	for pid := int32(os.Getpid()); pid > 0; {
		if seen[pid] {
			return Identity{}, errors.New("cyclic process ancestry")
		}
		seen[pid] = true
		if pid == p.pid {
			ancestor = true
		}
		parent, err := ps.NewProcessWithContext(ctx, pid)
		if err != nil {
			return Identity{}, err
		}
		next, err := parent.PpidWithContext(ctx)
		if err != nil {
			return Identity{}, err
		}

		pid = next
	}
	return Identity{PID: p.pid, User: user, Command: command, CreatedMS: created, UIDs: uids, Kernel: flags&0x00200000 != 0, Ancestor: ancestor, Cgroups: CgroupUnits(string(cg))}, nil
}
