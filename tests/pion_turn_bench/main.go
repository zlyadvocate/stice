// SPDX-License-Identifier: MPL-2.0
// pion-based TURN bandwidth benchmark (A->B relay through the same TURN server).
//
// Usage:
//
//	turn-bench -host 192.168.3.223 -port 3478 -user testuser -pass 123456 \
//	    -mode turn-udp -pkts 20000 -window 256
//
// For turn-tcp:
//
//	turn-bench ... -mode turn-tcp -pkts 40000 -window 64
//
// Both A and B allocate a relay on the same TURN server. A transmits toward B's
// relayed address; B receives. This mirrors test_coturn_bench's A->B bulk test.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/turn/v5"
)

const pktSize = 1200 // payload copied to/from the relay, matching stice bench

func main() {
	var host, user, pass, mode string
	var port int
	var pkts, window int
	var durationSec float64
	flag.StringVar(&host, "host", "", "TURN server address")
	flag.IntVar(&port, "port", 3478, "TURN server port")
	flag.StringVar(&user, "user", "", "TURN username")
	flag.StringVar(&pass, "pass", "", "TURN password")
	flag.StringVar(&mode, "mode", "turn-udp", "turn-udp | turn-tcp")
	flag.IntVar(&pkts, "pkts", 20000, "number of packets to send")
	flag.IntVar(&window, "window", 256, "max in-flight packets")
	flag.Float64Var(&durationSec, "dur", 0, "if >0, fixed-duration send (pkts becomes soft cap)")
	flag.Parse()

	server := net.JoinHostPort(host, fmt.Sprint(port))
	if user == "" || pass == "" {
		log.Fatal("-user and -pass are required")
	}

	switch mode {
	case "turn-udp":
		runUDP(server, user, pass, pkts, window, time.Duration(durationSec*float64(time.Second)))
	case "turn-tcp":
		runTCP(server, user, pass, pkts, window, time.Duration(durationSec*float64(time.Second)))
	default:
		log.Fatalf("unknown mode %q", mode)
	}
}

// newClient dials the TURN server control connection and allocates relay(s).
func newClient(server, user, pass, mode string) (*turn.Client, error) {
	var conn net.PacketConn
	var err error
	if mode == "turn-udp" {
		conn, err = net.ListenPacket("udp4", "0.0.0.0:0")
	} else {
		c, derr := net.Dial("tcp", server)
		if derr != nil {
			return nil, derr
		}
		conn = turn.NewSTUNConn(c)
	}
	if err != nil {
		return nil, fmt.Errorf("control dial: %w", err)
	}

	cfg := &turn.ClientConfig{
		STUNServerAddr: server,
		TURNServerAddr: server,
		Conn:           conn,
		Username:       user,
		Password:       pass,
		Realm:          "",
	}
	cl, err := turn.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("new client: %w", err)
	}
	if err := cl.Listen(); err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	return cl, nil
}

// --- turn-udp ---
func runUDP(server, user, pass string, pkts, window int, dur time.Duration) {
	clientA, err := newClient(server, user, pass, "turn-udp")
	if err != nil {
		log.Fatal(err)
	}
	defer clientA.Close()
	clientB, err := newClient(server, user, pass, "turn-udp")
	if err != nil {
		log.Fatal(err)
	}
	defer clientB.Close()

	relayA, err := clientA.Allocate()
	if err != nil {
		log.Fatalf("allocate A: %v", err)
	}
	defer relayA.Close()
	relayB, err := clientB.Allocate()
	if err != nil {
		log.Fatalf("allocate B: %v", err)
	}
	defer relayB.Close()

	addrB := relayB.LocalAddr().(*net.UDPAddr)
	log.Printf("A relay=%s B relay=%s", relayA.LocalAddr(), addrB)

	// B creates a permission toward A so coturn forwards A's frames to B.
	if _, err := relayB.WriteTo([]byte{0x00}, relayA.LocalAddr()); err != nil {
		log.Fatalf("B probe write: %v", err)
	}

	// B reader thread.
	var recvCount atomic.Int64
	var recvBytes atomic.Int64
	doneB := make(chan struct{})
	go func() {
		buf := make([]byte, 1600)
		for {
			n, _, rerr := relayB.ReadFrom(buf)
			if rerr != nil {
				return
			}
			recvCount.Add(1)
			recvBytes.Add(int64(n))
			_ = doneB
		}
	}()

	var sent atomic.Int64
	start := time.Now()
	// progress reporter
	go func() {
		for {
			time.Sleep(2 * time.Second)
			rcv := recvCount.Load()
			s := sent.Load()
			fmt.Printf("  ... %d sent, %d received\n", s, rcv)
		}
	}()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		payload := make([]byte, pktSize)
		inflight := int64(0)
		i := int64(0)
		for {
			if dur > 0 && time.Since(start) >= dur {
				return
			}
			if pkts > 0 && i >= int64(pkts) {
				return
			}
			if inflight >= int64(window) {
				time.Sleep(time.Millisecond)
				continue
			}
			binary.BigEndian.PutUint32(payload[:4], uint32(i))
			if _, werr := relayA.WriteTo(payload, addrB); werr != nil {
				log.Printf("write err: %v", werr)
				time.Sleep(time.Millisecond)
				continue
			}
			i++
			inflight = sent.Add(1) - recvCount.Load()
		}
	}()
	wg.Wait()
	// small settle so last packets drain
	time.Sleep(500 * time.Millisecond)
	elapsed := time.Since(start)

	rcvd := recvCount.Load()
	sentN := sent.Load()
	lost := sentN - rcvd
	goodput := float64(recvBytes.Load()) * 8.0 / elapsed.Seconds() / 1e6
	fmt.Printf("turn-udp: sent=%d received=%d lost=%d (%.2f%%) goodput=%.1fMbps elapsed=%.2fs\n",
		sentN, rcvd, lost, pct(lost, sentN), goodput, elapsed.Seconds())
	ok := "PASS"
	if lost > 0 || sentN == 0 {
		ok = "FAIL"
	}
	fmt.Printf("RESULT %s\n", ok)
	os.Exit(0)
}

// --- turn-tcp (RFC 6062 Mode-B: B passive accept, A active dial) ---
func runTCP(server, user, pass string, pkts, window int, dur time.Duration) {
	clientA, err := newClient(server, user, pass, "turn-tcp")
	if err != nil {
		log.Fatal(err)
	}
	defer clientA.Close()
	clientB, err := newClient(server, user, pass, "turn-tcp")
	if err != nil {
		log.Fatal(err)
	}
	defer clientB.Close()

	allocA, err := clientA.AllocateTCP()
	if err != nil {
		log.Fatalf("allocateTCP A: %v", err)
	}
	allocB, err := clientB.AllocateTCP()
	if err != nil {
		log.Fatalf("allocateTCP B: %v", err)
	}

	addrB := allocB.Addr().(*net.TCPAddr)
	log.Printf("A relay=%s B relay=%s", allocA.Addr(), addrB)

	// B accepts the incoming relayed connection.
	type accRes struct {
		conn net.Conn
		err  error
	}
	accCh := make(chan accRes, 1)
	go func() {
		c, aerr := allocB.Accept()
		accCh <- accRes{c, aerr}
	}()

	// A dials B's relayed TCP address (RFC 6062 active mode).
	dataConn, err := allocA.DialTCP("tcp", nil, addrB)
	if err != nil {
		log.Fatalf("dialtcp: %v", err)
	}
	defer dataConn.Close()

	ar := <-accCh
	if ar.err != nil {
		log.Fatalf("accept: %v", ar.err)
	}
	connB := ar.conn
	defer connB.Close()
	log.Printf("TCP data connection established")

	// B reader thread.
	var recvCount atomic.Int64
	var recvBytes atomic.Int64
	go func() {
		buf := make([]byte, 1600)
		for {
			n, rerr := connB.Read(buf)
			if rerr != nil {
				return
			}
			recvCount.Add(1)
			recvBytes.Add(int64(n))
		}
	}()

	var sent atomic.Int64
	start := time.Now()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		payload := make([]byte, pktSize)
		i := int64(0)
		for {
			if dur > 0 && time.Since(start) >= dur {
				return
			}
			if pkts > 0 && i >= int64(pkts) {
				return
			}
			binary.BigEndian.PutUint32(payload[:4], uint32(i))
			if _, werr := dataConn.Write(payload); werr != nil {
				log.Printf("write err: %v", werr)
				time.Sleep(time.Millisecond)
				continue
			}
			i++
			sent.Add(1)
		}
	}()
	wg.Wait()
	// drain
	time.Sleep(500 * time.Millisecond)
	elapsed := time.Since(start)

	rcvd := recvCount.Load()
	sentN := sent.Load()
	lost := sentN - rcvd
	goodput := float64(recvBytes.Load()) * 8.0 / elapsed.Seconds() / 1e6
	fmt.Printf("turn-tcp: sent=%d received=%d lost=%d (%.2f%%) goodput=%.1fMbps elapsed=%.2fs\n",
		sentN, rcvd, lost, pct(lost, sentN), goodput, elapsed.Seconds())
	ok := "PASS"
	if lost > 0 || sentN == 0 {
		ok = "FAIL"
	}
	fmt.Printf("RESULT %s\n", ok)
	os.Exit(0)
}

func pct(lost, sent int64) float64 {
	if sent == 0 {
		return 0
	}
	return 100.0 * float64(lost) / float64(sent)
}