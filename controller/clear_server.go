package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
)

type clearReq struct {
	SrcIP   string `json:"src_ip"`
	SrcPort uint16 `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort uint16 `json:"dst_port"`
}

// hostToNetIP: net.IP(4) -> uint32 matching the kernel's network-order key.
func hostToNetIP(ip net.IP) uint32 {
	return uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
}

func startClearServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/clear", func(w http.ResponseWriter, r *http.Request) {
		var req clearReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		if reassemblerInstance == nil || reassemblerInstance.writeFlowVerdict == nil {
			http.Error(w, "not ready", 503)
			return
		}
		si := net.ParseIP(req.SrcIP).To4()
		di := net.ParseIP(req.DstIP).To4()
		if si == nil || di == nil {
			http.Error(w, "bad ip", 400)
			return
		}
		fk := FlowMapKey{
			SrcIP:   hostToNetIP(si),
			DstIP:   hostToNetIP(di),
			SrcPort: htons(req.SrcPort),
			DstPort: htons(req.DstPort),
			Proto:   6,
		}
		if err := reassemblerInstance.writeFlowVerdict(fk, 0); err != nil {
			log.Printf("clear: write failed: %v", err)
			http.Error(w, "write failed", 500)
			return
		}
		log.Printf("FLOW CLEARED: %s:%d -> %s:%d", req.SrcIP, req.SrcPort, req.DstIP, req.DstPort)
		w.WriteHeader(200)
	})
	log.Println("clearance server on 127.0.0.1:9095")
	if err := http.ListenAndServe("127.0.0.1:9095", mux); err != nil {
		log.Printf("clearance server error: %v", err)
	}
}
