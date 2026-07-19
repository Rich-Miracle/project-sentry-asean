package main

import (
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	flowIdleTimeout = 30 * time.Second // flush flow if no new packets for this long
	flowCheckTick   = 5 * time.Second  // how often we sweep for stale flows
	tcpFlagFIN      = 0x01
	tcpFlagRST      = 0x04
)

// FlowKey uniquely identifies a flow by its 5-tuple.
// Protocol is implicit (TCP) since the kernel hook only emits TCP.
type FlowKey struct {
	SrcIP    uint32
	DestIP   uint32
	SrcPort  uint16
	DestPort uint16
}

func (k FlowKey) String() string {
	src := ipToString(k.SrcIP)
	dst := ipToString(k.DestIP)
	return fmt.Sprintf("%s:%d->%s:%d", src, k.SrcPort, dst, k.DestPort)
}

func ipToString(raw uint32) string {
	b := make([]byte, 4)
	// kernel writes network-order bytes into a uint32; binary.LittleEndian.Uint32
	// gave us the raw bytes in order, so just present them as IPv4.
	b[0] = byte(raw)
	b[1] = byte(raw >> 8)
	b[2] = byte(raw >> 16)
	b[3] = byte(raw >> 24)
	return net.IP(b).String()
}

// segment is one captured chunk of a flow.
type segment struct {
	seq  uint32
	data []byte
}

// flowState is one in-progress flow being reassembled.
type flowState struct {
	key       FlowKey
	segments  []segment
	totalSize int
	finSeen   bool
	rstSeen   bool
	lastSeen  time.Time
	capped    bool // true if cap was hit and we gave up on full reassembly
}

// Reassembler buffers packets per 5-tuple and rebuilds payloads.
type Reassembler struct {
	mu      sync.Mutex
	flows   map[FlowKey]*flowState
	cap     int // per-flow byte cap
	done    chan struct{}
	writeVerdict func(destIP uint32, verdict uint8) error // set by loader
}

// NewReassembler creates a reassembler with the given per-flow cap.
func NewReassembler(perFlowCap int) *Reassembler {
	r := &Reassembler{
		flows: make(map[FlowKey]*flowState),
		cap:   perFlowCap,
		done:  make(chan struct{}),
	}
	go r.timeoutSweeper()
	return r
}

// Close stops the timeout sweeper goroutine.
func (r *Reassembler) Close() {
	close(r.done)
}

// Ingest accepts one packet event from the kernel and adds it to its flow.
func (r *Reassembler) Ingest(e *Event) {
	key := FlowKey{
		SrcIP: e.SrcIP, DestIP: e.DestIP,
		SrcPort: e.SrcPort, DestPort: e.DestPort,
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	fs, ok := r.flows[key]
	if !ok {
		fs = &flowState{key: key, lastSeen: time.Now()}
		r.flows[key] = fs
	}
	fs.lastSeen = time.Now()

	// Track FIN/RST regardless of payload.
	if e.TCPFlags&tcpFlagFIN != 0 {
		fs.finSeen = true
	}
	if e.TCPFlags&tcpFlagRST != 0 {
		fs.rstSeen = true
	}

	// Append payload (if any) as a segment.
	if e.PayloadLen > 0 && !fs.capped {
		if fs.totalSize+int(e.PayloadLen) > r.cap {
			fs.capped = true
			log.Printf("REASSEMBLER: flow %s exceeded %d-byte cap, falling back",
				key, r.cap)
		} else {
			data := make([]byte, e.PayloadLen)
			copy(data, e.Payload[:e.PayloadLen])
			fs.segments = append(fs.segments, segment{seq: e.Seq, data: data})
			fs.totalSize += int(e.PayloadLen)
		}
	}

	// Decide whether to flush now.
	if fs.finSeen || fs.rstSeen || fs.capped {
		r.flushLocked(key, fs)
	}
}

// flushLocked must be called with r.mu held. It reassembles and removes the flow.
func (r *Reassembler) flushLocked(key FlowKey, fs *flowState) {
	delete(r.flows, key)

	if fs.capped {
		log.Printf("REASSEMBLER: flow %s flushed (capped, fallback to jurisdiction-only)",
			key)
		return
	}

	// Sort segments by TCP sequence number (handles out-of-order/retransmits).
	sort.Slice(fs.segments, func(i, j int) bool {
		return fs.segments[i].seq < fs.segments[j].seq
	})

	// Concatenate, de-duplicating overlapping seqs naively (later seq wins).
	// For PoC: simple concat is good enough; retransmits are usually identical.
	var rebuilt []byte
	seen := make(map[uint32]bool)
	for _, s := range fs.segments {
		if seen[s.seq] {
			continue
		}
		seen[s.seq] = true
		rebuilt = append(rebuilt, s.data...)
	}

	reason := "FIN"
	if fs.rstSeen {
		reason = "RST"
	}
	log.Printf("REASSEMBLER: flow %s complete via %s — %d bytes",
		key, reason, len(rebuilt))

	// --- Step 9: evaluate the reassembled payload via the AI agent ---
	if len(rebuilt) == 0 {
		return // nothing to inspect
	}

	// Resolve jurisdiction from dest_ip.
	je := resolveJurisdiction(key.DestIP)
	destIPStr := ipToString(key.DestIP)

	// Call the AI agent (runs in a goroutine so we don't block the sweeper;
	// but for PoC clarity we do it inline here).
	go func(k FlowKey, payload []byte, j jurisdictionEntry, ipStr string) {
		flowID := k.String()
		resp := evaluateFlow(flowID, ipStr, int(k.DestPort),
			j.Jurisdiction, j.Classification, payload, "text/plain")

		log.Printf("AI VERDICT for %s: %s (pii=%v types=%v) — %s",
			flowID, resp.Verdict, resp.PiiDetected, resp.PiiTypes, resp.Justification)

		// Write the verdict back to verdict_map.
		// Skip for the test-mirror IP so the mirror survives repeated tests.
		if r.writeVerdict != nil && ipStr != testMirrorIP {
			var v uint8 = 1 // BLOCK
			if resp.Verdict == "ALLOW" {
				v = 0
			}
			if err := r.writeVerdict(k.DestIP, v); err != nil {
				log.Printf("failed to write verdict_map: %v", err)
			} else {
				log.Printf("verdict_map updated: %s -> %s", ipStr, resp.Verdict)
			}
		}
	}(key, rebuilt, je, destIPStr)
}

// timeoutSweeper flushes flows that have gone idle.
func (r *Reassembler) timeoutSweeper() {
	t := time.NewTicker(flowCheckTick)
	defer t.Stop()
	for {
		select {
		case <-r.done:
			return
		case now := <-t.C:
			r.mu.Lock()
			for k, fs := range r.flows {
				if now.Sub(fs.lastSeen) > flowIdleTimeout {
					log.Printf("REASSEMBLER: flow %s idle timeout, flushing", k)
					r.flushLocked(k, fs)
				}
			}
			r.mu.Unlock()
		}
	}
}
