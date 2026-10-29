package registry

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/identity"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

func endpointProbeFailure(err error) TestResult {
	var e *upstream.Error
	if !errors.As(err, &e) {
		e = &upstream.Error{Class: upstream.ClassConfig, Message: "The endpoint cannot be checked with its current configuration."}
	}
	return TestResult{Err: e}
}

func (s *Service) probeEndpoint(ctx context.Context, sv dbgen.McpServer, row dbgen.McpServerEndpoint, trigger string, a authz.Actor, known []dbgen.ListMCPCapabilityFingerprintsRow) TestResult {
	ep, err := s.endpointNetwork(ctx, sv, row)
	if err != nil {
		return endpointProbeFailure(err)
	}
	t := upstream.Target{URL: ep.URL, Credentials: ep.Credentials, ServerID: sv.ID.String(), ServerSlug: sv.Slug, Timeout: timeout(sv)}
	if trigger == TriggerManual {
		actual := sv
		actual.URL = row.URL
		token, fail := s.testIdentity(ctx, a, actual)
		if fail != nil {
			return TestResult{Err: fail}
		}
		if token != "" {
			t.IdentityHeader, t.IdentityValue = identity.Header(t.AuthorizationHeader(), token)
		}
	}
	d, err := s.client.Discover(ctx, t)
	res := TestResult{Latency: d.Latency, ServerName: d.ServerName, ServerVersion: d.ServerVersion, ProtocolVersion: d.ProtocolVersion, Protocol: d.Protocol}
	if err != nil {
		res = endpointProbeFailure(err)
		res.Latency = d.Latency
		return res
	}
	if len(known) == 0 {
		res.Err = &upstream.Error{Class: upstream.ClassConfig, Reason: "endpoint_definition_unverified", Message: "Read the primary's capabilities before validating an additional endpoint."}
		return res
	}
	for _, expected := range known {
		found := false
		for _, cap := range d.Capabilities {
			if cap.Kind == expected.Kind && cap.Name == expected.Name && cap.Fingerprint == expected.Fingerprint {
				found = true
				break
			}
		}
		if !found {
			res.Err = &upstream.Error{Class: upstream.ClassNotAllowed, Reason: "endpoint_definition_mismatch", Message: "The endpoint's advertised capabilities differ from the stored primary definitions."}
			return res
		}
	}
	res.OK, res.Counts = true, upstream.CountKinds(d.Capabilities)
	return res
}

func (s *Service) checkExtraEndpoints(ctx context.Context, sv dbgen.McpServer, trigger string, a authz.Actor) {
	rows, err := s.q.ListMCPServerEndpoints(ctx, sv.ID)
	if err != nil {
		s.log.DebugContext(ctx, "could not list endpoint health targets", "server", sv.ID, "err", err)
		return
	}
	if len(rows) == 0 {
		return
	}
	modeErr := checkEndpointServer(sv, false)
	if tls, err := loadTLS(ctx, s.q, sv.ID); err != nil {
		modeErr = err
	} else if tls != nil {
		modeErr = endpointModeFailure()
	}
	known, definitionErr := s.q.ListMCPCapabilityFingerprints(ctx, []uuid.UUID{sv.ID})
	for _, row := range rows {
		if !row.Enabled {
			continue
		}
		var res TestResult
		if modeErr != nil {
			res = endpointProbeFailure(modeErr)
		} else if definitionErr != nil {
			res = endpointProbeFailure(definitionErr)
		} else {
			res = s.probeEndpoint(ctx, sv, row, trigger, a, known)
		}
		recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		err := recordEndpointCheck(recordCtx, s.q, sv.ID, row, res, trigger, by(a))
		cancel()
		if err != nil {
			s.log.DebugContext(ctx, "could not store endpoint health check", "server", sv.ID, "endpoint", row.ID, "err", err)
		}
	}
}

func recordEndpointCheck(ctx context.Context, q *dbgen.Queries, serverID uuid.UUID, row dbgen.McpServerEndpoint, res TestResult, trigger string, actor uuid.NullUUID) error {
	p := dbgen.InsertMCPServerEndpointHealthCheckParams{ServerID: serverID, EndpointID: row.ID, EndpointPosition: row.Position, Ok: res.OK, LatencyMs: int32(min(max(res.Latency.Milliseconds(), 0), 1<<31-1)), Trigger: trigger, Message: res.Note}
	if trigger == TriggerManual {
		p.TriggeredBy = actor
	}
	if res.Err != nil {
		class := res.Err.Class
		p.Ok, p.ErrorClass, p.Message = false, &class, upstream.SafeMessage(res.Err.Message)
		if status := res.Err.HTTPStatus; status >= 100 && status <= 599 {
			v := int32(status)
			p.HttpStatus = &v
		}
	}
	if _, err := q.InsertMCPServerEndpointHealthCheck(ctx, p); err != nil {
		return err
	}
	_, err := q.PruneMCPHealthChecks(ctx, dbgen.PruneMCPHealthChecksParams{ServerID: serverID, Keep: KeepChecks})
	return err
}
