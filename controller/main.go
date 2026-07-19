package main

import (
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"flag"

	"github.com/cilium/ebpf/ringbuf"
)

const ifaceName = "eth0" // workload's egress interface (shared netns)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("Project Sentry ASEAN — controller starting")
	
	flag.StringVar(&testMirrorIP, "test-mirror", "", "optional: dest IP to mirror+allow for testing")
	flag.Parse()
	// Load tc_hook.o and attach the TC egress hook (ebpf_loader.go).
	objs, tcLink, rb, err := loadAndAttach(ifaceName)
	if err != nil {
		log.Fatalf("load/attach failed: %v", err)
	}
	defer objs.Close()
	defer tcLink.Close()
	defer rb.Close()
	log.Printf("TC egress hook attached on %s", ifaceName)

	// Graceful shutdown on Ctrl-C.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		log.Println("shutting down...")
		rb.Close()
	}()

	// Ring buffer poll loop — drains kernel enforcement events.
	log.Println("listening for enforcement events...")
	for {
		record, err := rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("ring buffer closed, exiting")
				return
			}
			log.Printf("ring buffer read error: %v", err)
			continue
		}
		handleEvent(record.RawSample)
	}
}

func logEvent(ip string, port, payloadLen uint16) {
	log.Printf("EVENT: dest_ip=%s dest_port=%d payload_len=%d (unknown → PENDING → dropped)",
		ip, port, payloadLen)
}
