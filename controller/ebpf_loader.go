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

// FlowMapKey mirrors struct flow_key in kernel/tc_hook.h — 16 bytes, packed.
// All fields network byte order (the kernel builds the key from raw headers).
type FlowMapKey struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	_pad    [3]uint8
}

// htons swaps a host-order uint16 to network order (event ports are host order,
// but the kernel flow_key uses network order, so we convert on write).
func htons(v uint16) uint16 { return (v << 8) | (v >> 8) }

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
	// Gateway (routing, model download, DNS egress) — infrastructure allowlist.
	if vm := coll.Maps["verdict_map"]; vm != nil {
		var gwKey uint32 = 0x01001EAC // 172.30.0.1
		var allow uint8 = 0
		if err := vm.Put(gwKey, allow); err != nil {
			log.Printf("warning: could not exempt gateway: %v", err)
		} else {
			log.Printf("control-plane exemption: 172.30.0.1 (gateway) -> ALLOW")
		}
	}
	// Mail server — mitmproxy delivers cleared mail here. (Phase 3 replaces this
	// blanket allow with per-flow clearance.)
	if vm := coll.Maps["verdict_map"]; vm != nil {
		var mailKey uint32 = 0x0A001EAC // 172.30.0.10
		var allow uint8 = 0
		if err := vm.Put(mailKey, allow); err != nil {
			log.Printf("warning: could not exempt mailserver: %v", err)
		} else {
			log.Printf("control-plane exemption: 172.30.0.10 (mailserver) -> ALLOW")
		}
	}
	// us-server — sanctioned upload endpoint. mitmproxy inspects the upload
	// then delivers here; the content plane governs what may be sent, the
	// kernel gate blocks uploads to any non-sanctioned destination.
	if vm := coll.Maps["verdict_map"]; vm != nil {
		var usUploadKey uint32 = 0x16001EAC // 172.30.0.22
		var allow uint8 = 0
		if err := vm.Put(usUploadKey, allow); err != nil {
			log.Printf("warning: could not exempt us-server upload endpoint: %v", err)
		} else {
			log.Printf("control-plane exemption: 172.30.0.22 (us-server, sanctioned upload) -> ALLOW")
		}
	}
	// VM host — return traffic for published-port services (UI, Grafana) goes
	// back to the host address; without this, default-deny drops the replies.
	if vm := coll.Maps["verdict_map"]; vm != nil {
		var hostKey uint32 = 0x8525A8C0 // 192.168.37.133
		var allow uint8 = 0
		if err := vm.Put(hostKey, allow); err != nil {
			log.Printf("warning: could not exempt VM host: %v", err)
		} else {
			log.Printf("control-plane exemption: 192.168.37.133 (VM host) -> ALLOW")
		}
	}
	// VMware host / client side — browser access from the host machine returns here.
	if vm := coll.Maps["verdict_map"]; vm != nil {
		var vmhostKey uint32 = 0x0125A8C0 // 192.168.37.1
		var allow uint8 = 0
		if err := vm.Put(vmhostKey, allow); err != nil {
			log.Printf("warning: could not exempt VMware host: %v", err)
		} else {
			log.Printf("control-plane exemption: 192.168.37.1 (VMware host) -> ALLOW")
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
	flowVerdictMap := coll.Maps["flow_verdict_map"]
	reassemblerInstance.writeFlowVerdict = func(k FlowMapKey, verdict uint8) error {
		if flowVerdictMap == nil {
			return fmt.Errorf("flow_verdict_map not loaded")
		}
		return flowVerdictMap.Put(k, verdict)
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
