package translatorcliproxy

import (
	"bytes"
	"context"
	"strings"

	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
	_ "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator/builtin"
)

func ToOpenAI(from sdktranslator.Format, model string, raw []byte, stream bool) []byte {
	return sdktranslator.TranslateRequest(from, sdktranslator.FormatOpenAI, model, raw, stream)
}

func FromOpenAINonStream(to sdktranslator.Format, model string, originalReq, translatedReq, raw []byte) []byte {
	var param any
	return sdktranslator.TranslateNonStream(context.Background(), sdktranslator.FormatOpenAI, to, model, originalReq, translatedReq, raw, &param)
}

func FromOpenAIStream(to sdktranslator.Format, model string, originalReq, translatedReq, streamBody []byte) []byte {
	var out bytes.Buffer
	var param any
	for _, line := range bytes.Split(streamBody, []byte("\n")) {
		trimmed := strings.TrimSpace(string(line))
		if trimmed == "" {
			continue
		}
		payload := append([]byte(nil), line...)
		if !bytes.HasPrefix(payload, []byte("data:")) {
			continue
		}
		chunks := sdktranslator.TranslateStream(context.Background(), sdktranslator.FormatOpenAI, to, model, originalReq, translatedReq, payload, &param)
		for i := range chunks {
			out.Write(chunks[i])
			if !bytes.HasSuffix(chunks[i], []byte("\n")) {
				out.WriteByte('\n')
			}
		}
	}
	return out.Bytes()
}

func ParseFormat(name string) sdktranslator.Format {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "openai", "openai-chat", "chat", "chat-completions":
		return sdktranslator.FormatOpenAI
	case "openai-response", "responses", "openai-responses":
		return sdktranslator.FormatOpenAIResponse
	case "claude", "anthropic":
		return sdktranslator.FormatClaude
	case "gemini", "google":
		return sdktranslator.FormatGemini
	case "gemini-cli", "geminicli":
		return sdktranslator.FormatGeminiCLI
	case "codex", "openai-codex":
		return sdktranslator.FormatCodex
	case "antigravity":
		return sdktranslator.FormatAntigravity
	default:
		return sdktranslator.FromString(name)
	}
}

func ToOpenAIByName(formatName, model string, raw []byte, stream bool) []byte {
	return ToOpenAI(ParseFormat(formatName), model, raw, stream)
}
