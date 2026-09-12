package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
)

var (
	listenHost = flag.String("host", "0.0.0.0", "Host address to listen on")
	listenPort = flag.Int("port", 9099, "TCP port to listen on")
)

func main() {
	flag.Parse()

	mux := http.NewServeMux()

	// Latency endpoint: returns immediate 200 OK
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong\n"))
	})

	// Throughput endpoint: streams requested number of megabytes
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		sizeMB := 50
		if s := r.URL.Query().Get("mb"); s != "" {
			if v, err := strconv.Atoi(s); err == nil && v > 0 {
				sizeMB = v
			}
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)

		chunk := make([]byte, 64*1024) // 64KB chunk
		for i := range chunk {
			chunk[i] = 'A'
		}

		totalBytes := int64(sizeMB) * 1024 * 1024
		written := int64(0)
		for written < totalBytes {
			toWrite := int64(len(chunk))
			if written+toWrite > totalBytes {
				toWrite = totalBytes - written
			}
			n, err := w.Write(chunk[:toWrite])
			if err != nil {
				return
			}
			written += int64(n)
		}
	})

	addr := fmt.Sprintf("%s:%d", *listenHost, *listenPort)
	log.Printf("[TargetServer] Serving HTTP on %s (/ping, /stream?mb=...)", addr)
	if err := http.ListenAndServe(addr, mux); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
