package handler

import (
	"net/http/httptest"
	"testing"
)

func TestBrowserReachableBaseURL(t *testing.T) {
	got := BrowserReachableBaseURL("http://0.0.0.0:28080")
	want := "http://localhost:28080"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestRequestOAuthRootFromHost(t *testing.T) {
	req := httptest.NewRequest("POST", "http://localhost:28080/oauth/device/code", nil)
	req.Host = "localhost:28080"
	got := RequestOAuthRoot(req, "http://0.0.0.0:28080", "")
	if got != "http://localhost:28080" {
		t.Fatalf("got %q want http://localhost:28080", got)
	}
}

func TestSamePublicOrigin(t *testing.T) {
	if !SamePublicOrigin("http://0.0.0.0:28080", "http://localhost:28080") {
		t.Fatal("0.0.0.0:28080 should match localhost:28080")
	}
	if SamePublicOrigin("http://localhost:3000", "http://localhost:28080") {
		t.Fatal("different ports should not match")
	}
}

func TestDeviceVerificationURLs(t *testing.T) {
	uri, complete := DeviceVerificationURLs("http://localhost:28080", "ABCD-EFGH")
	if uri != "http://localhost:28080/device/" {
		t.Fatalf("uri=%q", uri)
	}
	if complete != "http://localhost:28080/device/?user_code=ABCD-EFGH" {
		t.Fatalf("complete=%q", complete)
	}
}
