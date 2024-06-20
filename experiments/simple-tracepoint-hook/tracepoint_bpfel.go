// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadTracepoint returns the embedded CollectionSpec for tracepoint.
func loadTracepoint() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TracepointBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load tracepoint: %w", err)
	}

	return spec, err
}

// loadTracepointObjects loads tracepoint and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*tracepointObjects
//	*tracepointPrograms
//	*tracepointMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTracepointObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTracepoint()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// tracepointSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracepointSpecs struct {
	tracepointProgramSpecs
	tracepointMapSpecs
}

// tracepointSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracepointProgramSpecs struct {
	GetPidExecve *ebpf.ProgramSpec `ebpf:"get_pid_execve"`
}

// tracepointMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tracepointMapSpecs struct {
	Ringbuf *ebpf.MapSpec `ebpf:"ringbuf"`
}

// tracepointObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTracepointObjects or ebpf.CollectionSpec.LoadAndAssign.
type tracepointObjects struct {
	tracepointPrograms
	tracepointMaps
}

func (o *tracepointObjects) Close() error {
	return _TracepointClose(
		&o.tracepointPrograms,
		&o.tracepointMaps,
	)
}

// tracepointMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTracepointObjects or ebpf.CollectionSpec.LoadAndAssign.
type tracepointMaps struct {
	Ringbuf *ebpf.Map `ebpf:"ringbuf"`
}

func (m *tracepointMaps) Close() error {
	return _TracepointClose(
		m.Ringbuf,
	)
}

// tracepointPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTracepointObjects or ebpf.CollectionSpec.LoadAndAssign.
type tracepointPrograms struct {
	GetPidExecve *ebpf.Program `ebpf:"get_pid_execve"`
}

func (p *tracepointPrograms) Close() error {
	return _TracepointClose(
		p.GetPidExecve,
	)
}

func _TracepointClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed tracepoint_bpfel.o
var _TracepointBytes []byte
