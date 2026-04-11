package admin

import (
	"strings"

	"ds2api/internal/config"
)

func normalizeSettingsConfig(c *config.Config) {
	if c == nil {
		return
	}
	c.Admin.PasswordHash = strings.TrimSpace(c.Admin.PasswordHash)
	c.Embeddings.Provider = strings.TrimSpace(c.Embeddings.Provider)
}

func validateSettingsConfig(c config.Config) error {
	return config.ValidateConfig(c)
}

func validateRuntimeSettings(runtime config.RuntimeConfig) error {
	return config.ValidateRuntimeConfig(runtime)
}
