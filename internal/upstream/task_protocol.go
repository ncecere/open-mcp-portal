package upstream

import (
	"bytes"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// TasksExtension is the released 2026-07-28 extension, not experimental core
// tasks. These wire types alone do not negotiate, dispatch or authorize tasks.
const TasksExtension = "io.modelcontextprotocol/tasks"

const (
	MethodTasksGet    = "tasks/get"
	MethodTasksUpdate = "tasks/update"
	MethodTasksCancel = "tasks/cancel"

	TaskWorking       = "working"
	TaskInputRequired = "input_required"
	TaskCompleted     = "completed"
	TaskFailed        = "failed"
	TaskCancelled     = "cancelled"

	MaxTaskIDBytes    = 8 << 10
	MaxTaskTextBytes  = 4 << 10
	MaxTaskInputBytes = 16 << 10
	maxTaskInteger    = int64(1<<53 - 1)
)

// TaskState is validated upstream state. Its ID and payloads are untrusted,
// secret-bearing data: a gateway must rebuild a public result with its own
// durable handle, authorization, timeline, bounds and redaction. TTL/poll are
// integer milliseconds, never an unchecked time.Duration multiplication.
type TaskState struct {
	ID, Status, Message      string
	CreatedAt, LastUpdatedAt time.Time
	TTLMillis, PollMillis    *int64 // nil TTL means upstream unlimited, NOT portal unlimited
	InputRequests, Result    json.RawMessage
	Error                    *TaskExecutionError
}

type TaskExecutionError struct {
	Code    int64
	Message string
	Data    json.RawMessage
}

type taskWire struct {
	Type          *string         `json:"resultType"`
	ID            *string         `json:"taskId"`
	Status        *string         `json:"status"`
	Message       json.RawMessage `json:"statusMessage"`
	CreatedAt     *string         `json:"createdAt"`
	UpdatedAt     *string         `json:"lastUpdatedAt"`
	TTL           json.RawMessage `json:"ttlMs"`
	Poll          json.RawMessage `json:"pollIntervalMs"`
	InputRequests json.RawMessage `json:"inputRequests"`
	Result        json.RawMessage `json:"result"`
	Error         json.RawMessage `json:"error"`
}

func invalidTaskState() error {
	// Never echo IDs, payloads, server messages, timestamps or credential text.
	return &Error{Class: ClassBadResponse, Reason: "invalid_task_state", Message: "The server returned invalid task state."}
}

// ParseCreateTaskResult parses the flat Result & Task creation shape. A
// terminal seed need not contain the DetailedTask payload: obtain it via get.
func ParseCreateTaskResult(raw json.RawMessage) (*TaskState, error) {
	return parseTaskState(raw, true, "")
}

// ParseGetTaskResult enforces both the ordinary-result discriminator and the
// exact stored upstream identity, never a task ID supplied by a downstream user.
func ParseGetTaskResult(raw json.RawMessage, expectedID string) (*TaskState, error) {
	if expectedID == "" || len(expectedID) > MaxTaskIDBytes {
		return nil, invalidTaskState()
	}
	return parseTaskState(raw, false, expectedID)
}

func parseTaskState(raw json.RawMessage, create bool, expectedID string) (*TaskState, error) {
	if len(raw) > DefaultMaxResponseBytes || !utf8.Valid(raw) {
		return nil, invalidTaskState()
	}
	var w taskWire
	if json.Unmarshal(raw, &w) != nil || w.Type == nil || w.ID == nil || w.Status == nil || w.CreatedAt == nil || w.UpdatedAt == nil || len(w.TTL) == 0 {
		return nil, invalidTaskState()
	}
	want := "complete"
	if create {
		want = "task"
	}
	if *w.Type != want || *w.ID == "" || len(*w.ID) > MaxTaskIDBytes || (!create && *w.ID != expectedID) {
		return nil, invalidTaskState()
	}
	t := &TaskState{ID: *w.ID, Status: *w.Status}
	switch t.Status {
	case TaskWorking, TaskInputRequired, TaskCompleted, TaskFailed, TaskCancelled:
	default:
		return nil, invalidTaskState()
	}
	if len(*w.CreatedAt) > 100 || len(*w.UpdatedAt) > 100 {
		return nil, invalidTaskState()
	}
	var err error
	if t.CreatedAt, err = time.Parse(time.RFC3339Nano, *w.CreatedAt); err != nil {
		return nil, invalidTaskState()
	}
	if t.LastUpdatedAt, err = time.Parse(time.RFC3339Nano, *w.UpdatedAt); err != nil || t.LastUpdatedAt.Before(t.CreatedAt) {
		return nil, invalidTaskState()
	}
	if len(w.Message) > 0 {
		if bytes.Equal(bytes.TrimSpace(w.Message), []byte("null")) || json.Unmarshal(w.Message, &t.Message) != nil || len(t.Message) > MaxTaskTextBytes {
			return nil, invalidTaskState()
		}
	}
	if !bytes.Equal(bytes.TrimSpace(w.TTL), []byte("null")) {
		v, err := taskInteger(w.TTL, true)
		if err != nil {
			return nil, err
		}
		t.TTLMillis = &v
	}
	if len(w.Poll) > 0 {
		v, err := taskInteger(w.Poll, true)
		if err != nil {
			return nil, err
		}
		t.PollMillis = &v
	}
	if create {
		return t, nil // Unknown/variant payloads are not relayed from creation.
	}
	switch t.Status {
	case TaskInputRequired:
		if !taskObject(w.InputRequests) || len(w.InputRequests) > MaxTaskInputBytes {
			return nil, invalidTaskState()
		}
		t.InputRequests = bytes.Clone(w.InputRequests)
	case TaskCompleted:
		if !taskObject(w.Result) {
			return nil, invalidTaskState()
		}
		t.Result = bytes.Clone(w.Result)
	case TaskFailed:
		if !taskObject(w.Error) {
			return nil, invalidTaskState()
		}
		var e struct {
			Code    json.RawMessage `json:"code"`
			Message *string         `json:"message"`
			Data    json.RawMessage `json:"data"`
		}
		if json.Unmarshal(w.Error, &e) != nil || e.Message == nil || len(*e.Message) > MaxTaskTextBytes {
			return nil, invalidTaskState()
		}
		code, err := taskInteger(e.Code, false)
		if err != nil {
			return nil, err
		}
		t.Error = &TaskExecutionError{Code: code, Message: *e.Message, Data: bytes.Clone(e.Data)}
	}
	return t, nil
}

// ParseTaskAcknowledgement validates the empty standard-result shape of update
// and cancel. Ignore extensions, but never return raw ack fields as task state.
func ParseTaskAcknowledgement(raw json.RawMessage) error {
	if len(raw) > DefaultMaxResponseBytes || !utf8.Valid(raw) {
		return invalidTaskState()
	}
	var v struct {
		Type *string `json:"resultType"`
	}
	if json.Unmarshal(raw, &v) != nil || v.Type == nil || *v.Type != "complete" {
		return invalidTaskState()
	}
	return nil
}

func taskObject(raw json.RawMessage) bool {
	v := bytes.TrimSpace(raw)
	return len(v) > 0 && v[0] == '{' && json.Valid(v)
}

// JSON Schema integers include integral decimal/exponent spellings. Parse
// losslessly before enforcing the safe-integer range; ParseFloat would round
// 9007199254740991.1 into an accepted integer. Bound size/exponents before big
// arithmetic so a tiny malicious exponent cannot allocate unbounded memory.
func taskInteger(raw json.RawMessage, nonnegative bool) (int64, error) {
	v := strings.TrimSpace(string(raw))
	if len(v) == 0 || len(v) > 64 || !json.Valid([]byte(v)) || (v[0] != '-' && (v[0] < '0' || v[0] > '9')) {
		return 0, invalidTaskState()
	}
	if i := strings.IndexAny(v, "eE"); i >= 0 {
		exp, err := strconv.ParseInt(v[i+1:], 10, 16)
		if err != nil || exp < -32 || exp > 32 {
			return 0, invalidTaskState()
		}
	}
	r, ok := new(big.Rat).SetString(v)
	if !ok || !r.IsInt() || !r.Num().IsInt64() {
		return 0, invalidTaskState()
	}
	n := r.Num().Int64()
	if n < -maxTaskInteger || n > maxTaskInteger || (nonnegative && n < 0) {
		return 0, invalidTaskState()
	}
	return n, nil
}
