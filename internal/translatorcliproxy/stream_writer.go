package translatorcliproxy

import (
	"bytes"
	"context"
	"net/http"

	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
)

// OpenAIStreamTranslatorWriter translates OpenAI SSE output to another client format in real-time.
type OpenAIStreamTranslatorWriter struct {
	dst           http.ResponseWriter
	target        sdktranslator.Format
	model         string
	originalReq   []byte
	translatedReq []byte
	param         any
	statusCode    int
	headersSent   bool
	lineBuf       bytes.Buffer
}

func NewOpenAIStreamTranslatorWriter(dst http.ResponseWriter, target sdktranslator.Format, model string, originalReq, translatedReq []byte) *OpenAIStreamTranslatorWriter {
	return &OpenAIStreamTranslatorWriter{
		dst:           dst,
		target:        target,
		model:         model,
		originalReq:   originalReq,
		translatedReq: translatedReq,
		statusCode:    http.StatusOK,
	}
}

func (w *OpenAIStreamTranslatorWriter) Header() http.Header {
	return w.dst.Header()
}

func (w *OpenAIStreamTranslatorWriter) WriteHeader(statusCode int) {
	if w.headersSent {
		return
	}
	w.statusCode = statusCode
	w.headersSent = true
	w.dst.WriteHeader(statusCode)
}

func (w *OpenAIStreamTranslatorWriter) Write(p []byte) (int, error) {
	if !w.headersSent {
		w.WriteHeader(http.StatusOK)
	}
	if w.statusCode < 200 || w.statusCode >= 300 {
		return w.dst.Write(p)
	}
	w.lineBuf.Write(p)
	for {
		line, ok := w.readOneLine()
		if !ok {
			break
		}
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		if !bytes.HasPrefix(trimmed, []byte("data:")) {
			continue
		}
		chunks := sdktranslator.TranslateStream(context.Background(), sdktranslator.FormatOpenAI, w.target, w.model, w.originalReq, w.translatedReq, trimmed, &w.param)
		for i := range chunks {
			if len(chunks[i]) == 0 {
				continue
			}
			if _, err := w.dst.Write(chunks[i]); err != nil {
				return len(p), err
			}
			if !bytes.HasSuffix(chunks[i], []byte("\n")) {
				if _, err := w.dst.Write([]byte("\n")); err != nil {
					return len(p), err
				}
			}
		}
		if f, ok := w.dst.(http.Flusher); ok {
			f.Flush()
		}
	}
	return len(p), nil
}

func (w *OpenAIStreamTranslatorWriter) Flush() {
	if f, ok := w.dst.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *OpenAIStreamTranslatorWriter) Unwrap() http.ResponseWriter {
	return w.dst
}

func (w *OpenAIStreamTranslatorWriter) readOneLine() ([]byte, bool) {
	b := w.lineBuf.Bytes()
	idx := bytes.IndexByte(b, '\n')
	if idx < 0 {
		return nil, false
	}
	line := append([]byte(nil), b[:idx]...)
	w.lineBuf.Next(idx + 1)
	return line, true
}
