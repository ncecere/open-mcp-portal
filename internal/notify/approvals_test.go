package notify

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func TestApprovalEventChoicesAndPrivateWebhookBoundary(t *testing.T) {
	for _, event := range []string{ApprovalRequested, ApprovalDecided} {
		if !ValidEvent(event) || !slices.Contains(Events, event) {
			t.Fatalf("unsupported approval event %s", event)
		}
		for _, choices := range [][]string{TeamDestinationEvents, PlatformDestinationEvents(false), PlatformDestinationEvents(true)} {
			if slices.Contains(choices, event) {
				t.Fatalf("private event %s offered to webhooks", event)
			}
		}
		if IsTeamEvent(event) || checkEvents([]string{event}, true, true) == nil || checkEvents([]string{event}, false, false) == nil {
			t.Fatal("private event was accepted by a destination")
		}
	}
}

func TestApprovalMessageAndSafeReceiptLinks(t *testing.T) {
	id := uuid.New()
	for _, tc := range []struct{ event, status, word string }{
		{ApprovalRequested, "pending", "requested"},
		{ApprovalDecided, "approved", "approved"},
		{ApprovalDecided, "denied", "denied"},
	} {
		raw, err := json.Marshal(approvalNotificationData{ApprovalID: id, ExposedName: "delete\r\n<img src=x onerror=alert(1)>", Status: tc.status})
		if err != nil {
			t.Fatal(err)
		}
		m := compose(dbgen.NotificationEvent{Event: tc.event, Payload: raw}, nil)
		if !strings.Contains(m.Title, tc.word) || strings.ContainsAny(m.Title, "\r\n") || m.Link == nil || m.Link.path() != "/approvals/"+id.String() {
			t.Fatalf("message=%+v", m)
		}
		s := unitService(t, nil)
		text, html, err := s.render(m)
		if err != nil || !strings.Contains(text, id.String()) || strings.Contains(html, "<img") || !strings.Contains(html, "&lt;img") {
			t.Fatalf("email escaping failed: %q %v", html, err)
		}
	}
	for _, malicious := range []string{"https://evil.example", "//evil.example", "../../settings", "bad?next=https://evil.example", ""} {
		if got := (&Link{Type: LinkApproval, ID: malicious}).path(); got != "/approvals" {
			t.Fatalf("unsafe receipt link %q became %q", malicious, got)
		}
	}
}
