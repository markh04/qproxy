package main

import (
	"log"
	"net"
	"github.com/quic-go/quic-go"
	"crypto/tls"
	"context"
	"time"
	"fmt"
	"io"
	"flag"
	"os"
	"errors"
)

func main() {

	local_addr := flag.String("listen", "127.0.0.1:8080", "Local address for inbound TCP connections")

	flag.Parse()

	cmd_args := flag.Args()
	dst_addr := &cmd_args[0]

	fmt.Println(*local_addr, "->", *dst_addr)

	src_addr_b, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		log.Fatal(err)
	}

	udpConn, err := net.ListenUDP("udp4", src_addr_b)
	if err != nil {
		log.Fatal(err)
	}

	tr := quic.Transport{ Conn: udpConn }

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tls := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}

	keylog, err := os.OpenFile(
		"private/sslkeys.log",
		os.O_WRONLY|os.O_CREATE|os.O_APPEND,
		0600,
	)
	if err != nil {
		log.Fatal(err)
	}

	tls.KeyLogWriter = keylog

	quic_config := &quic.Config{
		MaxIdleTimeout:        600 * time.Second,
		HandshakeIdleTimeout:  5 * time.Second,
		KeepAlivePeriod:       0,
		DisablePathMTUDiscovery: true,
		InitialStreamReceiveWindow:     512 * 1024,
		InitialConnectionReceiveWindow: 2 * 1024 * 1024,
		MaxConnectionReceiveWindow:     16 * 1024 * 1024,
		EnableDatagrams: true,
	}

	addr, err := net.ResolveUDPAddr("udp", *dst_addr)
	if err != nil {
		log.Fatal(err)
	}

	quic_conn, err := tr.Dial(ctx, addr, tls, quic_config)
	if err != nil {
		log.Fatal("Connection error:", err)
	}

	defer quic_conn.CloseWithError(0, "bye")

	tcp, err := net.Listen("tcp", *local_addr)
	if err != nil {
		log.Fatal(err)
	}

	go keepAliveSender(quic_conn)

	for {
		tcp_conn, err := tcp.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(quic_conn, &tcp_conn)
	}

}

func handleConnection(quic_conn *quic.Conn, tcp_conn_ *net.Conn) {
	tcp_conn, _ := (*tcp_conn_).(*net.TCPConn)

	stream, err := quic_conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Println(err)
		tcp_conn.SetLinger(0)
		tcp_conn.Close()
		return
	}
	defer stream.Close()


	done := make(chan struct{})

	go func() {
		_, err2 := io.Copy(stream, tcp_conn)
		if err2 != nil {
			if errors.Is(err2, io.EOF) {
				stream.Close()
			} else {
				stream.CancelWrite(0x10)
			}
		}
		done <- struct{}{}
	}()

	go func() {
		_, err2 := io.Copy(tcp_conn, stream)
		if err2 != nil {
			if !errors.Is(err, io.EOF) {
				tcp_conn.SetLinger(0)
			}
			tcp_conn.Close()
		}
		done <- struct{}{}
	}()

	<-done

}

func keepAliveSender(quic_conn *quic.Conn) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		go sendKeepAlive(quic_conn)
	}
}

func sendKeepAlive(quic_conn *quic.Conn) {
	quic_conn.SendDatagram([]byte("KEEP_ALIVE"))
}