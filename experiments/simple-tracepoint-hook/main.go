package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type ringbufData struct {
	timestamp uint64
	pid       uint32
	filename  [512]byte
}

func main() {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Error removing memlock:", err)
	}
	var objs tracepointObjects

	if err := loadTracepointObjects(&objs, nil); err != nil {
		log.Fatal("Error loading tracepoint objects:", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.GetPidExecve, nil)
	if err != nil {
		log.Fatal("Error attaching tracepoint:", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Ringbuf)
	if err != nil {
		log.Fatal("Error reading ringbuf:", err)
	}
	defer rd.Close()

	var ringData ringbufData
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			// read from RingBuf map
			// print the data
			record, err := rd.Read()
			if err != nil {
				log.Fatal("Error reading ringbuf:", err)
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ringData); err != nil {
				log.Print("Error reading ringbuf data:", err)
				continue
			}

			log.Printf("PID: %d, Filename: %s\n", ringData.pid, string(ringData.filename[:]))
		case <-stop:
			log.Println("Exiting...")
			return
		}

	}

}
