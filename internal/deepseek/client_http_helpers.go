package deepseek

import (
	"bufio"
	"compress/gzip"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
)

func readResponseBody(resp *http.Response) ([]byte, error) {
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	var reader io.Reader = resp.Body
	switch encoding {
	case "gzip":
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer func() { _ = gz.Close() }()
		reader = gz
	case "br":
		reader = brotli.NewReader(resp.Body)
	}
	return io.ReadAll(reader)
}

func preview(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 160 {
		return s[:160]
	}
	return s
}

func ScanSSELines(resp *http.Response, onLine func([]byte) bool) error {
	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)
	for scanner.Scan() {
		if !onLine(scanner.Bytes()) {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}
