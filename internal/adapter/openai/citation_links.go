package openai

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var citationMarkerPattern = regexp.MustCompile(`(?i)\[citation:\s*(\d+)\]`)

func replaceCitationMarkersWithLinks(text string, links map[int]string) string {
	if strings.TrimSpace(text) == "" || len(links) == 0 {
		return text
	}
	return citationMarkerPattern.ReplaceAllStringFunc(text, func(match string) string {
		sub := citationMarkerPattern.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		idx, err := strconv.Atoi(strings.TrimSpace(sub[1]))
		if err != nil || idx <= 0 {
			return match
		}
		url := strings.TrimSpace(links[idx])
		if url == "" {
			return match
		}
		return fmt.Sprintf("[%d](%s)", idx, url)
	})
}
