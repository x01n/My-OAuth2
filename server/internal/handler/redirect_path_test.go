package handler

import "testing"

func TestSafeReturnPath(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "empty", raw: "", want: defaultReturnPath},
		{name: "dashboard", raw: "/dashboard", want: "/dashboard"},
		{name: "oauth authorize query", raw: "/oauth/authorize?client_id=app&scope=openid", want: "/oauth/authorize?client_id=app&scope=openid"},
		{name: "external https", raw: "https://evil.example/callback", want: defaultReturnPath},
		{name: "external http", raw: "http://evil.example/callback", want: defaultReturnPath},
		{name: "protocol relative", raw: "//evil.example/callback", want: defaultReturnPath},
		{name: "javascript scheme", raw: "javascript:alert(1)", want: defaultReturnPath},
		{name: "relative path", raw: "dashboard", want: defaultReturnPath},
		{name: "control character", raw: "/dashboard\r\nLocation:https://evil.example", want: defaultReturnPath},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeReturnPath(tt.raw); got != tt.want {
				t.Fatalf("safeReturnPath(%q)=%q want %q", tt.raw, got, tt.want)
			}
		})
	}
}
