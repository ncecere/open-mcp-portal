package httpapi_test

import "testing"

func TestCatalogSearchRejectsMalformedText(t *testing.T) {
	e := newRegistryEnv(t)
	for name, query := range map[string]string{"invalid_byte": "%FF", "overlong_utf8": "%C0%AF", "surrogate": "%ED%A0%80", "nul": "%00", "embedded_nul": "before%00after"} {
		t.Run(name, func(t *testing.T) {
			code, ec := e.outsider.call("GET", "/v1/catalog/servers?q="+query, nil, nil, nil)
			mustCode(t, "non-text catalog search", code, ec, 400, "invalid_search")
		})
	}
}
