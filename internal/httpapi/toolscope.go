package httpapi

import (
	"encoding/json"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/toolscope"
)

func fromAPIToolScope(s *apitypes.ToolScope) []byte {
	if s == nil {
		return nil
	}
	b, _ := json.Marshal(s)
	return b
}

func toAPIToolScope(raw []byte) *apitypes.ToolScope {
	s := toolscope.Stored(raw)
	if s == nil {
		return nil
	}
	var out apitypes.ToolScope
	_ = json.Unmarshal(toolscope.JSON(s), &out)
	return &out
}

// Generated nullable pointers cannot distinguish omission from explicit null.
// RawMessage shadows the embedded field while keeping strict decoding of the
// generated fields (including rejection of unknown top-level properties).
type serviceAccountScopeUpdate struct {
	apitypes.ServiceAccountUpdate
	ToolScope json.RawMessage `json:"toolScope"`
}

type oauthScopeDecision struct {
	apitypes.OAuthConsentDecision
	ToolScope json.RawMessage `json:"toolScope"`
}
