package main

import (
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type ringbufData struct {
	timestamp uint64
	pid       uint32
	filename  [512]byte
}

func main() {
	err := rlimit.RemoveMemlock()
	if err != nil {
		log.Fatal("Removing memlock:", err)
	}

	var objs tracepointObjects
	err = loadTracepointObjects(objs, nil)
	if err != nil {
		log.Fatal("Loading tracepoint objects:", err)
	}
	defer objs.Close()

	tp, tp_err := link.Tracepoint(
		"syscalls",
		"sys_enter_execve",
		objs.GetPidExecve,
		nil,
	)

	if tp_err != nil {
		log.Fatal("Attaching tracepoint:", tp_err)
	}
	defer tp.Close()

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			// read from RingBuf map
			// print the data
			var ringData ringbufData
			err = objs.Ringbuf.LookupAndDelete(ringbufData{}, &ringData)
			if err != nil {
				log.Fatal("Reading ringbuf:", err)
			}
			log.Printf("Timestamp: %d, PID: %d, Filename: %s\n", ringData.timestamp, ringData.pid, string(ringData.filename[:]))
		case <-stop:
			log.Println("Exiting...")
			return
		}

	}

}
