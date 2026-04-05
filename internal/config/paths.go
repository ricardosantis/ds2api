package config

import (
	"os"
	"path/filepath"
	"strings"
)

func BaseDir() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return cwd
}

func IsVercel() bool {
	return strings.TrimSpace(os.Getenv("VERCEL")) != "" || strings.TrimSpace(os.Getenv("NOW_REGION")) != ""
}

func ResolvePath(envKey, defaultRel string) string {
	raw := strings.TrimSpace(os.Getenv(envKey))
	if raw != "" {
		if filepath.IsAbs(raw) {
			return raw
		}
		return filepath.Join(BaseDir(), raw)
	}
	return filepath.Join(BaseDir(), defaultRel)
}

func ConfigPath() string {
	return ResolvePath("DS2API_CONFIG_PATH", "config.json")
}

func WASMPath() string {
	return ResolvePath("DS2API_WASM_PATH", "sha3_wasm_bg.7b9ca65ddd.wasm")
}

func RawStreamSampleRoot() string {
	return ResolvePath("DS2API_RAW_STREAM_SAMPLE_ROOT", "tests/raw_stream_samples")
}

func StaticAdminDir() string {
	return ResolvePath("DS2API_STATIC_ADMIN_DIR", "static/admin")
}
