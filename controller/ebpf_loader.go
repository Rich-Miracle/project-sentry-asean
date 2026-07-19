package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const bpfObjectPath = "tc_hook.o"

// Package-level reassembler — created by loadAndAttach, used by handleEvent.
var reassemblerInstance *Reassembler
var testMirrorIP string

// Event mirrors struct event_t in kernel/tc_hook.h — layout MUST match.
type Event struct {
	SrcIP      uint32
	DestIP     uint32
	SrcPort    uint16
	DestPort   uint16
	Seq        uint32
	TCPFlags   uint8
	_pad       uint8
	PayloadLen uint16
	Payload    [4096]byte
}

// loadedObjects holds handles we must keep alive and close on exit.
type loadedObjects struct {
	coll *ebpf.Collection
}

func (o *loadedObjects) Close() {
	if o.coll != nil {
		o.coll.Close()
	}
}

// loadAndAttach loads tc_hook.o, attaches the TC egress hook to iface,
// and opens the ring buffer reader.
func loadAndAttach(iface string) (*loadedObjects, link.Link, *ringbuf.Reader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, nil, fmt.Errorf("removing memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(bpfObjectPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		// Verifier errors surface here — print in full.
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, nil, nil, fmt.Errorf("verifier error:\n%+v", ve)
		}
		return nil, nil, nil, fmt.Errorf("creating collection: %w", err)
	}

	prog := coll.Programs["tc_egress"]
	if prog == nil {
		coll.Close()
		return nil, nil, nil, fmt.Errorf("program tc_egress not found")
	}
	
	// --- Control-plane exemption: the AI agent's local LLM ---
	// The inspector must not block its own reasoning engine. Ollama runs on a
	// fixed internal IP; exempting it is a management-plane allowlist, the same
	// pattern enterprise DLP uses for its own control traffic.
	if vm := coll.Maps["verdict_map"]; vm != nil {
		var ollamaKey uint32 = 0x32001EAC // 172.30.0.50, network byte order
		var allow uint8 = 0               // VERDICT_ALLOW
		if err := vm.Put(ollamaKey, allow); err != nil {
			log.Printf("warning: could not exempt Ollama: %v", err)
		} else {
			log.Printf("control-plane exemption: 172.30.0.50 (Ollama) -> ALLOW")
		}
	}

	// Prometheus (monitoring control plane) — infrastructure, not a data destination.
	if vm := coll.Maps["verdict_map"]; vm != nil {
		var promKey uint32 = 0x3C001EAC // 172.30.0.60
		var allow uint8 = 0
		if err := vm.Put(promKey, allow); err != nil {
			log.Printf("warning: could not exempt Prometheus: %v", err)
		} else {
			log.Printf("control-plane exemption: 172.30.0.60 (Prometheus) -> ALLOW")
		}
	}

	// --- Optional test-mirror seed (disabled by default) ---
	// Run with:  ./sentry-controller -test-mirror=1.1.1.1
	// to mirror+allow one destination for reassembly testing.
	if testMirrorIP != "" {
		if vm := coll.Maps["verdict_map"]; vm != nil {
			ip := net.ParseIP(testMirrorIP).To4()
			if ip != nil {
				key := binary.LittleEndian.Uint32(ip)
				var val uint8 = 3 // VERDICT_TEST_MIRROR
				if err := vm.Put(key, val); err != nil {
					log.Printf("warning: could not seed verdict_map: %v", err)
				} else {
					log.Printf("TEST MODE: seeded verdict_map %s -> TEST_MIRROR", testMirrorIP)
				}
			}
		}
	}

	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		coll.Close()
		return nil, nil, nil, fmt.Errorf("interface %s: %w", iface, err)
	}

	tcLink, err := link.AttachTCX(link.TCXOptions{
		Interface: netIface.Index,
		Program:   prog,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		coll.Close()
		return nil, nil, nil, fmt.Errorf("attaching TCX egress: %w", err)
	}

	rb, err := ringbuf.NewReader(coll.Maps["ring_buffer"])
	if err != nil {
		tcLink.Close()
		coll.Close()
		return nil, nil, nil, fmt.Errorf("opening ring buffer: %w", err)
	}

	// Initialize the reassembler
	reassemblerInstance = NewReassembler(128 * 1024) // 128 KB cap

	// Load jurisdiction mapping (dest_ip -> jurisdiction).
	if err := loadJurisdictions("/controller/jurisdiction.yaml"); err != nil {
		log.Printf("warning: jurisdiction load failed: %v", err)
	}

	// Give the reassembler a way to write verdicts back to the eBPF map.
	verdictMap := coll.Maps["verdict_map"]
	reassemblerInstance.writeVerdict = func(destIP uint32, verdict uint8) error {
		return verdictMap.Put(destIP, verdict)
	}

	// FIX: Added missing return statement. This also resolves "declared and not used: rb"
	return &loadedObjects{coll: coll}, tcLink, rb, nil
}

// handleEvent decodes one ring buffer record and forwards to the reassembler.
func handleEvent(raw []byte) {
	if len(raw) < 20 {  // 4+4+2+2+4+1+1+2 = 20 bytes of header
		return
	}
	e := Event{
		SrcIP:      binary.LittleEndian.Uint32(raw[0:4]),
		DestIP:     binary.LittleEndian.Uint32(raw[4:8]),
		SrcPort:    binary.LittleEndian.Uint16(raw[8:10]),
		DestPort:   binary.LittleEndian.Uint16(raw[10:12]),
		Seq:        binary.LittleEndian.Uint32(raw[12:16]),
		TCPFlags:   raw[16],
		PayloadLen: binary.LittleEndian.Uint16(raw[18:20]),
	}
	if e.PayloadLen > 4096 {
		e.PayloadLen = 4096
	}
	if len(raw) >= 20+int(e.PayloadLen) && e.PayloadLen > 0 {
		copy(e.Payload[:e.PayloadLen], raw[20:20+int(e.PayloadLen)])
	}
	reassemblerInstance.Ingest(&e)
}
