package main

import (
	"log"
	"net"
	"io"
	"github.com/quic-go/quic-go"
	"context"
	"time"
	"os"
	"flag"
	"errors"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"fmt"
)



func main() {

	local_addr := flag.String("listen", "127.0.0.1:8443", "Local address for inbound TCP connections")
	max_pto := flag.Duration("max-pto", 30*time.Second, "Maximum value of PTO backoff in seconds")
	max_idle := flag.Duration("max-idle", 3600*time.Second, "Maximum period of network inactivity in seconds")
	ping_period := flag.Duration("ping-period", 60*time.Second, "Period between sending PING-frames in seconds")

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

	var tls_cert tls.Certificate
	var err error

	if len(cmd_args) == 3 {
		ssl_crt_path := cmd_args[1]
		ssl_key_path := cmd_args[2]
		tls_cert, err = tls.LoadX509KeyPair(ssl_crt_path, ssl_key_path)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		tls_cert = generateCert()
	}
	tls_config := &tls.Config {
		Certificates: []tls.Certificate{tls_cert},
		NextProtos: []string{"h3"},
	}

	local_addr_b, err := net.ResolveUDPAddr("udp", *local_addr)

	keylog, err := os.OpenFile(
		"sslkeys.log",
		os.O_WRONLY|os.O_CREATE|os.O_APPEND,
		0600,
	)
	if err != nil {
		log.Fatal(err)
	}

	tls_config.KeyLogWriter = keylog


	udpConn, err := net.ListenUDP("udp4", local_addr_b)
	if err != nil {
		log.Fatal(err)
	}

	tr := quic.Transport{ Conn: udpConn }
	quic_config := &quic.Config{
		Versions: []quic.Version{quic.Version2, quic.Version1},
		MaxIdleTimeout:        *max_idle,
		HandshakeIdleTimeout:  10 * time.Second,
		KeepAlivePeriod:       *ping_period,
		MaxPTODuration: *max_pto,
	}

	ln, err := tr.Listen(tls_config, quic_config)
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn, dst_addr)
	}

}

func handleConnection(conn *quic.Conn, dst_addr *string) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Println(err)
			break
		}
		go handleStream(stream, dst_addr)
	}
}

func handleStream(stream *quic.Stream, dst_addr *string) {
	defer stream.Close()
	log.Println(stream)
	conn, err := net.Dial("tcp", *dst_addr)
	if err != nil {
    	log.Println(err)
    	stream.CancelWrite(0x10)
    	return
	}
	tcp_conn, _ := conn.(*net.TCPConn)

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
			if errors.Is(err, io.EOF) {
				tcp_conn.SetLinger(0)
			}
			tcp_conn.Close()
		}
		done <- struct{}{}
	}()

	<-done

}

func generateCert() tls.Certificate {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test RSA Cert"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}
	certDER, _ := x509.CreateCertificate(
		rand.Reader, &template, &template, &key.PublicKey, key,
	)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)

	return cert

}
