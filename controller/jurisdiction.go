package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// jurisdictionYAML mirrors compose/jurisdiction.yaml structure.
type jurisdictionYAML struct {
	Destinations []struct {
		IP             string `yaml:"ip"`
		Name           string `yaml:"name"`
		Jurisdiction   string `yaml:"jurisdiction"`
		Classification string `yaml:"classification"`
	} `yaml:"destinations"`
}

// jurisdictionEntry is the resolved info for one destination.
type jurisdictionEntry struct {
	Jurisdiction   string
	Classification string
}

// jurisdictionMap: dest_ip (as uint32, network order) -> entry.
var jurisdictionMap = map[uint32]jurisdictionEntry{}

// loadJurisdictions reads the YAML mapping into jurisdictionMap.
func loadJurisdictions(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	var y jurisdictionYAML
	if err := yaml.Unmarshal(data, &y); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	for _, d := range y.Destinations {
		ip := net.ParseIP(d.IP).To4()
		if ip == nil {
			log.Printf("jurisdiction: skipping invalid IP %q", d.IP)
			continue
		}
		key := binary.LittleEndian.Uint32(ip)
		jurisdictionMap[key] = jurisdictionEntry{
			Jurisdiction:   d.Jurisdiction,
			Classification: d.Classification,
		}
	}
	log.Printf("loaded %d jurisdiction entries", len(jurisdictionMap))
	return nil
}

// resolveJurisdiction looks up a dest_ip (uint32, as the kernel provides it).
// Unknown destinations are treated as UNKNOWN / NON_EQUIVALENT (fail-secure).
func resolveJurisdiction(destIP uint32) jurisdictionEntry {
	if e, ok := jurisdictionMap[destIP]; ok {
		return e
	}
	return jurisdictionEntry{Jurisdiction: "UNKNOWN", Classification: "NON_EQUIVALENT"}
}
