package textclean

import "regexp"

var referenceMarkerPattern = regexp.MustCompile(`(?i)\[reference:\s*\d+\]`)

func StripReferenceMarkers(text string) string {
	if text == "" {
		return text
	}
	return referenceMarkerPattern.ReplaceAllString(text, "")
}
