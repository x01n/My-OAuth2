package handler

import (
	"net/url"
	"strings"
)

const defaultReturnPath = "/dashboard"

func safeReturnPath(raw string) string {
	if raw == "" {
		return defaultReturnPath
	}
	if strings.ContainsAny(raw, "\r\n\t") {
		return defaultReturnPath
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return defaultReturnPath
	}
	if parsed.IsAbs() || parsed.Host != "" || parsed.Scheme != "" {
		return defaultReturnPath
	}
	if !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(raw, "//") {
		return defaultReturnPath
	}
	if parsed.Path == "" {
		return defaultReturnPath
	}
	return raw
}
