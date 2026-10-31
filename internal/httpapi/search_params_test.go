package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSearchRejectsNonTextInput(t *testing.T) {
	for name, encoded := range map[string]string{"invalid_byte": "%FF", "overlong_utf8": "%C0%AF", "surrogate": "%ED%A0%80", "nul": "%00", "embedded_nul": "before%00after"} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			value, ok := search(response, httptest.NewRequest(http.MethodGet, "/v1/catalog/servers?q="+encoded, nil))
			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil && response.Code == http.StatusBadRequest {
				t.Fatal("validation response is not JSON")
			}
			if ok || value != nil || response.Code != http.StatusBadRequest || body.Error.Code != "invalid_search" {
				t.Fatalf("non-text search accepted: ok=%v status=%d code=%q", ok, response.Code, body.Error.Code)
			}
		})
	}
}

func TestSearchValidUTF8AndBounds(t *testing.T) {
	for _, text := range []string{strings.Repeat("x", 200), strings.Repeat("é", 100), strings.Repeat("😀", 50), `100%_\ literal`} {
		response := httptest.NewRecorder()
		value, ok := search(response, httptest.NewRequest(http.MethodGet, "/v1/catalog/servers?q="+url.QueryEscape(" \t"+text+"\u2003"), nil))
		if !ok || value == nil || *value != text {
			t.Fatal("valid literal UTF-8/byte-boundary search changed")
		}
	}
	for _, text := range []string{strings.Repeat("x", 201), strings.Repeat("é", 101)} {
		response := httptest.NewRecorder()
		value, ok := search(response, httptest.NewRequest(http.MethodGet, "/v1/catalog/servers?q="+url.QueryEscape(text), nil))
		if ok || value != nil || response.Code != http.StatusBadRequest {
			t.Fatal("oversized search was accepted")
		}
	}
	for _, query := range []string{"", "?q=", "?q=" + url.QueryEscape(" \t\u2003\n")} {
		response := httptest.NewRecorder()
		value, ok := search(response, httptest.NewRequest(http.MethodGet, "/v1/catalog/servers"+query, nil))
		if !ok || value != nil {
			t.Fatal("empty-query compatibility changed")
		}
	}
}
