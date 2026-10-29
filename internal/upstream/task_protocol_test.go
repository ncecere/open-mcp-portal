package upstream

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func taskFixture(t *testing.T, kind, status string, change func(map[string]any)) json.RawMessage {
	t.Helper()
	v := map[string]any{"resultType": kind, "taskId": "private-upstream-task-579814", "status": status,
		"createdAt": "2026-10-29T12:00:00Z", "lastUpdatedAt": "2026-10-29T12:00:01Z", "ttlMs": nil}
	if change != nil {
		change(v)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestTaskProtocolFlatCreationAndTerminalSeed(t *testing.T) {
	for _, status := range []string{TaskWorking, TaskInputRequired, TaskCompleted, TaskFailed, TaskCancelled} {
		t.Run(status, func(t *testing.T) {
			in := taskFixture(t, "task", status, func(v map[string]any) { v["result"] = map[string]any{"untrusted": true} })
			got, err := ParseCreateTaskResult(in)
			if err != nil || got.Status != status || got.ID != "private-upstream-task-579814" || got.TTLMillis != nil || len(got.Result) != 0 || got.Error != nil || len(got.InputRequests) != 0 {
				t.Fatalf("flat creation: %+v %v", got, err)
			}
		})
	}
	if _, err := ParseCreateTaskResult(json.RawMessage(`{"resultType":"task","task":{"taskId":"secret"}}`)); err == nil {
		t.Fatal("accepted obsolete nested task shape")
	}
}

func TestTaskProtocolGetVariantsAndCompletedToolError(t *testing.T) {
	for _, status := range []string{TaskWorking, TaskInputRequired, TaskCompleted, TaskFailed, TaskCancelled} {
		t.Run(status, func(t *testing.T) {
			raw := taskFixture(t, "complete", status, func(v map[string]any) {
				switch status {
				case TaskInputRequired:
					v["inputRequests"] = map[string]any{"k": map[string]any{"method": "elicitation/create"}}
				case TaskCompleted:
					v["result"] = map[string]any{"content": []any{}, "isError": true}
				case TaskFailed:
					v["error"] = map[string]any{"code": -32603, "message": "Untrusted server message", "data": map[string]any{"retry": false}}
				}
			})
			got, err := ParseGetTaskResult(raw, "private-upstream-task-579814")
			if err != nil || got.Status != status {
				t.Fatalf("get variant: %+v %v", got, err)
			}
			if status == TaskCompleted && (!bytes.Contains(got.Result, []byte(`"isError":true`)) || got.Error != nil) {
				t.Fatal("tool error misclassified as failed task")
			}
			if status == TaskFailed && (got.Error == nil || got.Error.Code != -32603) {
				t.Fatal("lost protocol execution error")
			}
		})
	}
	for _, status := range []string{TaskInputRequired, TaskCompleted, TaskFailed} {
		if _, err := ParseGetTaskResult(taskFixture(t, "complete", status, nil), "private-upstream-task-579814"); err == nil {
			t.Fatal("accepted missing status-specific payload", status)
		}
	}
}

func TestTaskProtocolIntegersAreLosslessAndBounded(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int64
	}{{"0", 0}, {"1000", 1000}, {"1000.0", 1000}, {"1e3", 1000}, {"9.007199254740991e15", maxTaskInteger}} {
		raw := taskFixture(t, "task", TaskWorking, func(v map[string]any) {
			v["ttlMs"], v["pollIntervalMs"] = json.RawMessage(tc.raw), json.RawMessage(tc.raw)
		})
		got, err := ParseCreateTaskResult(raw)
		if err != nil || got.TTLMillis == nil || *got.TTLMillis != tc.want || got.PollMillis == nil || *got.PollMillis != tc.want {
			t.Fatalf("integer %s: %+v %v", tc.raw, got, err)
		}
	}
	for _, invalid := range []string{`"1000"`, "true", "-1", "1.25", "9007199254740992", "9007199254740991.1", "1e1000000000", "0.0000000000000000001"} {
		for _, field := range []string{"ttlMs", "pollIntervalMs"} {
			raw := taskFixture(t, "task", TaskWorking, func(v map[string]any) { v[field] = json.RawMessage(invalid) })
			if _, err := ParseCreateTaskResult(raw); err == nil {
				t.Fatalf("accepted %s=%s", field, invalid)
			}
		}
	}
	if _, err := ParseCreateTaskResult(taskFixture(t, "task", TaskWorking, func(v map[string]any) { v["pollIntervalMs"] = nil })); err == nil {
		t.Fatal("null polling interval is not an integer")
	}
}

func TestTaskProtocolRefusalsNeverEchoPrivateState(t *testing.T) {
	changes := []func(map[string]any){
		func(v map[string]any) { delete(v, "ttlMs") },
		func(v map[string]any) { v["status"] = "private-secret-invalid-status" },
		func(v map[string]any) { v["taskId"] = "" },
		func(v map[string]any) { v["taskId"] = strings.Repeat("X", MaxTaskIDBytes+1) },
		func(v map[string]any) { v["createdAt"] = "private-secret-invalid-date" },
		func(v map[string]any) { v["lastUpdatedAt"] = "2026-10-29T11:59:59Z" },
		func(v map[string]any) { v["statusMessage"] = nil },
		func(v map[string]any) { v["statusMessage"] = strings.Repeat("X", MaxTaskTextBytes+1) },
	}
	for i, change := range changes {
		_, err := ParseCreateTaskResult(taskFixture(t, "task", TaskWorking, change))
		var ue *Error
		if !errors.As(err, &ue) || ue.Class != ClassBadResponse || ue.Reason != "invalid_task_state" || strings.Contains(err.Error(), "private-secret") || strings.Contains(err.Error(), "579814") {
			t.Fatalf("unsafe refusal %d: %v", i, err)
		}
	}
	if _, err := ParseGetTaskResult(taskFixture(t, "complete", TaskWorking, nil), "different-private-upstream-task"); err == nil {
		t.Fatal("accepted a different upstream task identity")
	}
	if _, err := ParseGetTaskResult(taskFixture(t, "task", TaskWorking, nil), "private-upstream-task-579814"); err == nil {
		t.Fatal("accepted stale SEP get discriminator instead of released complete")
	}
	large := taskFixture(t, "complete", TaskInputRequired, func(v map[string]any) {
		v["inputRequests"] = map[string]any{"x": strings.Repeat("X", MaxTaskInputBytes)}
	})
	if _, err := ParseGetTaskResult(large, "private-upstream-task-579814"); err == nil {
		t.Fatal("unbounded task input request payload")
	}
}

func TestTaskProtocolAcknowledgementsAreNotTaskState(t *testing.T) {
	for _, raw := range []string{`{"resultType":"complete"}`, `{"resultType":"complete","future":true}`} {
		if err := ParseTaskAcknowledgement(json.RawMessage(raw)); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{`{}`, `{"resultType":"task"}`, `{"resultType":"input_required"}`, `null`, `[]`, `{"resultType":null}`, `{"resultType":"complete"} {}`} {
		if err := ParseTaskAcknowledgement(json.RawMessage(raw)); err == nil {
			t.Fatal("accepted invalid ack", raw)
		}
	}
}

func FuzzTaskProtocolParsers(f *testing.F) {
	f.Add([]byte(`{"resultType":"complete"}`))
	f.Add([]byte(`{"resultType":"task","taskId":"x","status":"working","createdAt":"2026-10-29T12:00:00Z","lastUpdatedAt":"2026-10-29T12:00:00Z","ttlMs":null}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseCreateTaskResult(raw)
		_, _ = ParseGetTaskResult(raw, "x")
		_ = ParseTaskAcknowledgement(raw)
	})
}
