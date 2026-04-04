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
	"os/signal"
	"syscall"
)

func main() {

	local_addr := flag.String("listen", "127.0.0.1:8080", "Local address for inbound TCP connections")
	max_pto := flag.Duration("max-pto", 3*time.Second, "Maximum value of PTO backoff in seconds")
	max_idle := flag.Duration("max-idle", 3600*time.Second, "Maximum period of network inactivity in seconds")
	ping_period := flag.Duration("ping-period", 20*time.Second, "Period between sending PING-frames in seconds")
	ignore_cert := flag.Bool("skip-cert-verify", false, "Skip checking the server SSL certificate")
	keylog_file := flag.String("keylog", "", "Keylog file to store session keys")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] <input>\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Arguments:")
		fmt.Fprintln(os.Stderr, "  dist_addr    Destination address")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

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
		InsecureSkipVerify: *ignore_cert,
		NextProtos:         []string{"h3"},
	}

	if *keylog_file != "" {
		keylog, err := os.OpenFile(
			*keylog_file,
			os.O_WRONLY|os.O_CREATE|os.O_APPEND,
			0600,
		)
		if err != nil {
			log.Fatal(err)
		}

		tls.KeyLogWriter = keylog
	}

	quic_config := &quic.Config{
		MaxIdleTimeout:        *max_idle,
		HandshakeIdleTimeout:  2 * time.Second,
		KeepAlivePeriod:       *ping_period,
		MaxPTODuration:        *max_pto,
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

	loc_addr, err := net.ResolveTCPAddr("tcp", *local_addr)
	if err != nil {
		log.Fatal(err)
	}

	tcp, err := net.ListenTCP("tcp", loc_addr)
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Exiting...")
			return
		default:
			tcp.SetDeadline(time.Now().Add(1 * time.Second))
			tcp_conn, err := tcp.Accept()
			if err != nil {
				//log.Println(err)
				continue
			}
			go handleConnection(quic_conn, &tcp_conn)
		}
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
