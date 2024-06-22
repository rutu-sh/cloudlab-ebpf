package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// func intArrToString(arr [512]int8) string {
// 	str := ""
// 	for _, v := range arr {
// 		if v == 0 {
// 			break
// 		}
// 		str += strconv.Itoa(int(v))
// 	}
// 	return str
// }

func convertToString(arr [512]int8) string {
	var b []byte
	for _, v := range arr {
		if v == 0 { // Stop at the first null byte
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
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

	rd, err := ringbuf.NewReader(objs.EventRingbuf)
	if err != nil {
		log.Fatal("Error reading ringbuf:", err)
	}
	defer rd.Close()

	rd.SetDeadline(time.Now().Add(time.Second * 10))

	var ringData tracepointEvent
	tick := time.Tick(time.Second * 5)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			// read from RingBuf map
			// print the data
			if rd.BufferSize() == 0 {
				log.Println("No data in ring buffer")
				continue
			}
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Received signal, exiting..")
					return
				}
				log.Fatal("Error reading ringbuf:", err)
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ringData); err != nil {
				log.Print("Error reading ringbuf data:", err)
				continue
			}

			// display pid and filename
			log.Printf("Timestamp: %d PID: %d, Filename: %s\n", ringData.Timestamp, ringData.Pid, convertToString(ringData.Filename))

		case <-stop:
			log.Println("Exiting...")
			return
		}

	}

}
