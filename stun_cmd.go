package main

// calltun stun-probe: measure the built-in STUN collection (plus any
// extra --stun servers) from THIS host — the tool for "which hosts work
// under which conditions" evaluations.

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// parseSTUNResponse walks the STUN attribute TLVs for XOR-MAPPED-ADDRESS
// (0x0020) or MAPPED-ADDRESS (0x0001).
func parseSTUNResponse(msg, cookie []byte) (net.IP, uint16, error) {
	if len(msg) < 20 {
		return nil, 0, fmt.Errorf("short response")
	}
	off := 20
	for off+4 <= len(msg) {
		attr := binary.BigEndian.Uint16(msg[off : off+2])
		l := int(binary.BigEndian.Uint16(msg[off+2 : off+4]))
		if off+4+l > len(msg) {
			break
		}
		v := msg[off+4 : off+4+l]
		if (attr == 0x0020 || attr == 0x0001) && len(v) >= 8 {
			port := binary.BigEndian.Uint16(v[2:4])
			ip := make([]byte, 4)
			copy(ip, v[4:8])
			if attr == 0x0020 {
				port ^= 0x2112
				for i := range ip {
					ip[i] ^= cookie[i]
				}
			}
			return net.IP(ip), port, nil
		}
		off += 4 + l + (l % 4) // attributes are padded to 4 bytes
	}
	return nil, 0, fmt.Errorf("no mapped address attribute")
}

func cmdStunProbe(ctx context.Context, args []string) error {
	fs := newFlagSet("stun-probe")
	var c commonFlags
	registerCommon(fs, &c) // brings --stun; extra servers go there
	fs.Parse(args)
	initLog(false)

	servers := defaultSTUNServers
	if e := splitList(c.stun); len(e) > 0 && !strings.EqualFold(c.stun, "none") {
		servers = append(servers, splitList(normalizeStun(c.stun))...)
	}

	type result struct {
		server string
		ok     bool
		lat    time.Duration
		mapped string
		err    string
	}
	results := make(chan result, len(servers))
	for _, srv := range servers {
		go func(srv string) {
			r := result{server: srv}
			conn, err := net.DialTimeout("udp", srv, 3*time.Second)
			if err != nil {
				r.err = err.Error()
				results <- r
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			var txid [12]byte
			rand.Read(txid[:])
			req := make([]byte, 20)
			binary.BigEndian.PutUint16(req[0:2], 0x0001)
			binary.BigEndian.PutUint16(req[2:4], 0)
			binary.BigEndian.PutUint32(req[4:8], 0x2112A442)
			copy(req[8:20], txid[:])
			t0 := time.Now()
			if _, err := conn.Write(req); err != nil {
				r.err = err.Error()
				results <- r
				return
			}
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				r.err = err.Error()
				results <- r
				return
			}
			r.lat = time.Since(t0)
			ip, port, perr := parseSTUNResponse(buf[:n], req[4:8])
			if perr != nil {
				r.err = perr.Error()
			} else {
				r.ok = true
				r.mapped = fmt.Sprintf("%s:%d", ip, port)
			}
			results <- r
		}(srv)
	}

	var all []result
	for range servers {
		select {
		case r := <-results:
			all = append(all, r)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].ok != all[j].ok {
			return all[i].ok
		}
		return all[i].lat < all[j].lat
	})
	okCount := 0
	for _, r := range all {
		if r.ok {
			okCount++
			fmt.Printf("OK   %-32s %5dms  %s\n", r.server, r.lat.Milliseconds(), r.mapped)
		} else {
			fmt.Printf("FAIL %-32s %s\n", r.server, r.err)
		}
	}
	fmt.Printf("%d/%d reachable\n", okCount, len(all))
	if okCount == 0 {
		os.Exit(1)
	}

	// Phase 2: ONE socket against several servers — the mapping
	// comparison that classifies the NAT (the parallel probes above each
	// use their own socket, so their ports are never comparable).
	var reachable []string
	for _, r := range all {
		if r.ok && len(reachable) < 4 {
			reachable = append(reachable, r.server)
		}
	}
	fmt.Println("--- same-socket pass (NAT classification):")
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return err
	}
	defer conn.Close()
	seen := map[string]bool{}
	for _, srv := range reachable {
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var txid [12]byte
		rand.Read(txid[:])
		req := make([]byte, 20)
		binary.BigEndian.PutUint16(req[0:2], 0x0001)
		binary.BigEndian.PutUint32(req[4:8], 0x2112A442)
		copy(req[8:20], txid[:])
		raddr, err := net.ResolveUDPAddr("udp", srv)
		if err != nil {
			continue
		}
		if _, err := conn.WriteTo(req, raddr); err != nil {
			continue
		}
		buf := make([]byte, 1024)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			fmt.Printf("     %-32s no response\n", srv)
			continue
		}
		ip, port, perr := parseSTUNResponse(buf[:n], req[4:8])
		if perr != nil {
			fmt.Printf("     %-32s %s\n", srv, perr)
			continue
		}
		m := fmt.Sprintf("%s:%d", ip, port)
		seen[m] = true
		fmt.Printf("     %-32s %s\n", srv, m)
	}
	switch len(seen) {
	case 0:
		fmt.Println("NAT: no classification (no same-socket responses)")
	case 1:
		fmt.Println("NAT: mapping consistent across destinations -> endpoint-independent (cone; hole punching viable)")
	default:
		fmt.Println("NAT: mapping varies per destination -> endpoint-dependent (symmetric; direct punch unlikely)")
	}
	return nil
}
