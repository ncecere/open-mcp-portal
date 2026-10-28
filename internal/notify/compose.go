package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Link targets (the web app routes on them; docs/admin-overview.md).
const (
	LinkServer               = "server"
	LinkServers              = "servers"
	LinkReviewQueue          = "review_queue"
	LinkServiceAccount       = "service_account"
	LinkServiceConnections   = "service_connections"
	LinkAutomationTokens     = "automation_tokens"
	LinkTeamAutomationTokens = "team_automation_tokens"
	LinkAccountConnections   = "account_connections"
	LinkAccountAPIKeys       = "account_api_keys"
	LinkApproval             = "approval"
)

// Link is where an inbox row goes.
type Link struct {
	Type     string `json:"type"`
	ID       string `json:"id,omitempty"`
	TeamSlug string `json:"teamSlug,omitempty"`
}

// Message is an event as a person reads it: the inbox row, the email and the
// Slack text are built from it.
type Message struct {
	Title string
	Body  string
	Link  *Link
}

// teamInfo is the team an event belongs to.
type teamInfo struct {
	ID         uuid.UUID
	Slug, Name string
}

// clip cuts s to at most n characters (an ellipsis marks the cut) and keeps
// it on one line.
func clip(s string, n int) string {
	s = strings.Join(strings.Fields(strings.NewReplacer("\r", " ", "\n", " ", "\x00", "").Replace(s)), " ")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return strings.TrimSpace(string(r[:n-1])) + "…"
}

// nm delimits user-controlled text (a server's, team's or key's name) so it
// reads as a name and can't pass as part of the portal's own sentence.
func nm(s string) string { return "\"" + strings.ReplaceAll(clip(s, 100), "\"", "'") + "\"" }

func quoteAll(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = nm(n)
	}
	return out
}

func duration(d time.Duration) string {
	switch {
	case d < 2*time.Minute:
		return "a minute"
	case d < 2*time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// compose builds an event's message from its payload. An unknown shape
// yields a generic message rather than failing the delivery.
func compose(ev dbgen.NotificationEvent, team *teamInfo) Message {
	slug := ""
	if team != nil {
		slug = team.Slug
	}
	teamName := ""
	if team != nil {
		teamName = team.Name
	}
	m := Message{Title: ev.Event, Body: ""}
	switch ev.Event {
	case ApprovalRequested, ApprovalDecided:
		var d approvalNotificationData
		if json.Unmarshal(ev.Payload, &d) != nil || d.ApprovalID == uuid.Nil {
			break
		}
		m.Link = &Link{Type: LinkApproval, ID: d.ApprovalID.String()}
		if ev.Event == ApprovalRequested {
			m.Title = fmt.Sprintf("Approval requested for %s", nm(d.ExposedName))
			m.Body = "A sensitive tool call is waiting for review. Open the receipt to review it."
		} else {
			if d.Status != "approved" && d.Status != "denied" {
				break
			}
			m.Title = fmt.Sprintf("Approval for %s was %s", nm(d.ExposedName), d.Status)
			m.Body = "Open the receipt for its current status. Approval authorizes one attempt; it does not confirm execution."
		}
	case ServerUnhealthy:
		var d apitypes.ServerUnhealthyData
		if json.Unmarshal(ev.Payload, &d) != nil {
			break
		}
		m.Link = &Link{Type: LinkServer, ID: d.Server.Id.String(), TeamSlug: slug}
		if d.Reminder {
			m.Title = fmt.Sprintf("Server %s is still unhealthy", nm(d.Server.Name))
			hours := int32(0)
			if d.FailingHours != nil {
				hours = *d.FailingHours
			}
			m.Body = fmt.Sprintf("It has been failing for %s.", plural(int(hours), "hour", "hours"))
		} else {
			m.Title = fmt.Sprintf("Server %s is unhealthy", nm(d.Server.Name))
			m.Body = fmt.Sprintf("The last %s failed", plural(int(d.ConsecutiveFailures), "check", "checks"))
			if d.ErrorClass != nil && *d.ErrorClass != "" {
				m.Body += " (" + *d.ErrorClass + ")"
			}
			m.Body += ". Failing since " + d.Since.UTC().Format("2006-01-02 15:04 MST") + "."
		}
	case ServerRecovered:
		var d apitypes.ServerRecoveredData
		if json.Unmarshal(ev.Payload, &d) != nil {
			break
		}
		m.Link = &Link{Type: LinkServer, ID: d.Server.Id.String(), TeamSlug: slug}
		m.Title = fmt.Sprintf("Server %s recovered", nm(d.Server.Name))
		m.Body = "It was down for " + duration(time.Duration(d.DowntimeSeconds)*time.Second) + "."
	case CapabilityChanged:
		var d apitypes.CapabilityChangedData
		if json.Unmarshal(ev.Payload, &d) != nil {
			break
		}
		m.Link = &Link{Type: LinkServer, ID: d.Server.Id.String(), TeamSlug: slug}
		m.Title = fmt.Sprintf("Capabilities changed on %s", nm(d.Server.Name))
		var parts []string
		if d.ChangedCount > 0 {
			parts = append(parts, plural(int(d.ChangedCount), "changed capability", "changed capabilities"))
		}
		if d.NewCount > 0 {
			parts = append(parts, plural(int(d.NewCount), "new capability", "new capabilities"))
		}
		m.Body = strings.Join(parts, " and ") + " held back from the catalog until approved."
		if len(d.Capabilities) > 0 {
			names := make([]string, 0, 3)
			for _, c := range d.Capabilities[:min(3, len(d.Capabilities))] {
				names = append(names, c.Name)
			}
			m.Body += " " + strings.Join(quoteAll(names), ", ")
			if rest := int(d.ChangedCount+d.NewCount) - len(names); rest > 0 {
				m.Body += fmt.Sprintf(" and %d more", rest)
			}
			m.Body += "."
		}
	case PublishRequested:
		var d apitypes.PublishRequestedData
		if json.Unmarshal(ev.Payload, &d) != nil {
			break
		}
		m.Link = &Link{Type: LinkReviewQueue}
		m.Title = fmt.Sprintf("Review requested for %s", nm(d.Server.Name))
		m.Body = fmt.Sprintf("Team %s asked to publish it (%s).", nm(teamName), strings.ReplaceAll(string(d.Reason), "_", " "))
		if d.Note != nil && *d.Note != "" {
			m.Body += " Note: " + *d.Note
		}
	case PublishDecided:
		var d apitypes.PublishDecidedData
		if json.Unmarshal(ev.Payload, &d) != nil {
			break
		}
		m.Link = &Link{Type: LinkServer, ID: d.Server.Id.String(), TeamSlug: slug}
		m.Title = fmt.Sprintf("%s was %s", nm(d.Server.Name), d.Decision)
		m.Body = fmt.Sprintf("%s %s it.", nm(d.DecidedBy.Name), map[string]string{"approved": "approved", "rejected": "rejected"}[string(d.Decision)])
		if d.Note != nil && *d.Note != "" {
			m.Body += " Note: " + *d.Note
		}
	case ConnectionNeedsReconsent:
		var d apitypes.ConnectionNeedsReconsentData
		if json.Unmarshal(ev.Payload, &d) != nil {
			break
		}
		if ev.SubjectType == "service_connection" {
			m.Link = &Link{Type: LinkServiceConnections, TeamSlug: slug}
			m.Title = fmt.Sprintf("Reconnect the shared %s account", nm(d.Provider.Name))
			m.Body = "A shared connection owned by " + nm(teamName) + " needs re-consent. A team owner or admin must reconnect it under Service accounts > Connections so its assigned service accounts can use it again."
			break
		}
		m.Link = &Link{Type: LinkAccountConnections}
		m.Title = fmt.Sprintf("Reconnect %s", nm(d.Provider.Name))
		m.Body = "Your connection to " + nm(d.Provider.Name) + " lapsed. Connect again so tools that use it keep working."
		if d.Server != nil {
			m.Body = "Your sign-in to " + nm(d.Server.Name) + " lapsed. Connect again so its tools keep working for you."
		}
	case UpstreamSigninLapsed:
		var d apitypes.UpstreamSigninLapsedData
		if json.Unmarshal(ev.Payload, &d) != nil {
			break
		}
		m.Link = &Link{Type: LinkServer, ID: d.Server.Id.String(), TeamSlug: slug}
		m.Title = fmt.Sprintf("The sign-in that reads %s has lapsed", nm(d.Server.Name))
		m.Body = "An editor needs to sign in again so its capabilities can be read."
	case KeyExpiring:
		var d apitypes.KeyExpiringData
		if json.Unmarshal(ev.Payload, &d) != nil {
			break
		}
		kind := map[apitypes.KeyExpiringDataKeyKind]string{
			apitypes.KeyExpiringDataKeyKindPersonal: "API key", apitypes.KeyExpiringDataKeyKindServiceAccount: "Service account key",
			apitypes.KeyExpiringDataKeyKindPublisherToken: "Publisher token", apitypes.KeyExpiringDataKeyKindPlatformToken: "Platform token",
			apitypes.KeyExpiringDataKeyKindServerCertificate: "Client certificate of",
		}[d.KeyKind]
		m.Title = fmt.Sprintf("%s %s expires in %s", kind, nm(d.Name), plural(int(d.DaysLeft), "day", "days"))
		m.Body = "It stops working on " + d.ExpiresAt.UTC().Format("2006-01-02 15:04 MST") + ". Make a new one and replace it where it is used."
		if d.KeyKind == apitypes.KeyExpiringDataKeyKindServerCertificate {
			m.Body = "The server will refuse the portal's TLS client certificate after " + d.ExpiresAt.UTC().Format("2006-01-02 15:04 MST") +
				". Upload a renewed certificate and key in the server's TLS settings before then."
		}
		switch d.KeyKind {
		case apitypes.KeyExpiringDataKeyKindPersonal:
			m.Link = &Link{Type: LinkAccountAPIKeys}
		case apitypes.KeyExpiringDataKeyKindServiceAccount:
			m.Link = &Link{Type: LinkServiceAccount, TeamSlug: slug}
			if d.ServiceAccount != nil {
				m.Link.ID = d.ServiceAccount.Id.String()
			}
		case apitypes.KeyExpiringDataKeyKindPublisherToken:
			m.Link = &Link{Type: LinkTeamAutomationTokens, TeamSlug: slug}
		case apitypes.KeyExpiringDataKeyKindPlatformToken:
			m.Link = &Link{Type: LinkAutomationTokens}
		case apitypes.KeyExpiringDataKeyKindServerCertificate:
			if d.Server != nil {
				m.Link = &Link{Type: LinkServer, ID: d.Server.Id.String(), TeamSlug: slug}
			}
		}
	}
	m.Title, m.Body = clip(m.Title, 200), clip(m.Body, 500)
	return m
}

// path is the web app path of a link (docs/admin-overview.md, "Link targets").
func (l *Link) path() string {
	if l == nil {
		return ""
	}
	team := "/teams/" + url.PathEscape(l.TeamSlug)
	switch l.Type {
	case LinkApproval:
		id, err := uuid.Parse(l.ID)
		if err != nil || id == uuid.Nil {
			return "/approvals"
		}
		return "/approvals/" + id.String()
	case LinkServer:
		return team + "/servers/" + url.PathEscape(l.ID)
	case LinkServers:
		return team + "/servers?publishState=pending"
	case LinkReviewQueue:
		return "/admin/publishing"
	case LinkServiceAccount:
		if l.ID != "" {
			return team + "/service-accounts/" + url.PathEscape(l.ID)
		}
		return team + "/service-accounts"
	case LinkAutomationTokens:
		return "/admin/automation-tokens"
	case LinkTeamAutomationTokens:
		return team + "/settings?tab=automation-tokens"
	case LinkServiceConnections:
		return team + "/service-accounts?tab=connections"
	case LinkAccountConnections:
		return "/settings/connections"
	case LinkAccountAPIKeys:
		return "/settings/api-keys"
	}
	return "/"
}

// portalURL is the absolute link of a message.
func (s *Service) portalURL(l *Link) string {
	p := l.path()
	if p == "" {
		p = "/"
	}
	return strings.TrimRight(s.cfg.AppURL, "/") + p
}

// linkTarget converts a link to the API's LinkTarget.
func (l *Link) target() *apitypes.LinkTarget {
	if l == nil {
		return nil
	}
	out := &apitypes.LinkTarget{Type: apitypes.LinkTargetType(l.Type)}
	if l.ID != "" {
		id := l.ID
		out.Id = &id
	}
	if l.TeamSlug != "" {
		ts := l.TeamSlug
		out.TeamSlug = &ts
	}
	return out
}

// envelope is the body of a json webhook (apitypes.NotificationPayload).
type envelope struct {
	ID         uuid.UUID `json:"id"`
	Type       string    `json:"type"`
	Version    int       `json:"version"`
	OccurredAt time.Time `json:"occurredAt"`
	Instance   struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"instance"`
	Team *apitypes.TeamRef `json:"team"`
	URL  string            `json:"url"`
	Data json.RawMessage   `json:"data"`
}

// payload builds a json webhook's body: at most 8 KiB, no secrets, header
// values, call contents or addresses.
func (s *Service) payload(ev dbgen.NotificationEvent, team *teamInfo, msg Message) ([]byte, error) {
	e := envelope{ID: ev.PublicID, Type: ev.Event, Version: 1, OccurredAt: ev.OccurredAt.UTC(), URL: s.portalURL(msg.Link), Data: ev.Payload}
	e.Instance.Name, e.Instance.URL = s.cfg.InstanceName, s.cfg.AppURL
	if team != nil {
		e.Team = &apitypes.TeamRef{Id: team.ID, Slug: team.Slug, Name: team.Name}
	}
	if len(e.Data) == 0 {
		e.Data = json.RawMessage("{}")
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// slackText is a Slack-compatible destination's body: one line and a link,
// with & < > escaped, at most 3000 characters.
func (s *Service) slackText(msg Message) string {
	// & < > are Slack's markup (links, <!channel> mentions), and a zero-width
	// space after @ stops plain @channel and @here from reading as mentions.
	esc0 := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	esc := struct{ Replace func(string) string }{func(s string) string {
		return strings.ReplaceAll(esc0.Replace(s), "@", "@\u200b")
	}}
	link := ""
	if msg.Link != nil {
		link = " <" + s.portalURL(msg.Link) + "|Open>"
	}
	text := "[" + esc.Replace(s.cfg.InstanceName) + "] " + esc.Replace(msg.Title)
	if msg.Body != "" {
		text += ": " + esc.Replace(msg.Body)
	}
	if r := []rune(text); len(r) > 3000-len([]rune(link)) {
		text = string(r[:3000-len([]rune(link))-1]) + "…"
	}
	return text + link
}

func slackBody(text string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(map[string]string{"text": text})
	return bytes.TrimRight(b.Bytes(), "\n")
}
