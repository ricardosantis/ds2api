package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"ds2api/internal/auth"
	"ds2api/internal/deepseek"
)

type managedFilesAuthStub struct{}

func (managedFilesAuthStub) Determine(_ *http.Request) (*auth.RequestAuth, error) {
	return &auth.RequestAuth{
		UseConfigToken: true,
		DeepSeekToken:  "managed-token",
		CallerID:       "caller:test",
		AccountID:      "acct-123",
		TriedAccounts:  map[string]bool{},
	}, nil
}

func (managedFilesAuthStub) DetermineCaller(_ *http.Request) (*auth.RequestAuth, error) {
	return &auth.RequestAuth{
		UseConfigToken: true,
		DeepSeekToken:  "managed-token",
		CallerID:       "caller:test",
		AccountID:      "acct-123",
		TriedAccounts:  map[string]bool{},
	}, nil
}

func (managedFilesAuthStub) Release(_ *auth.RequestAuth) {}

type filesRouteDSStub struct {
	lastReq deepseek.UploadFileRequest
	upload  *deepseek.UploadFileResult
	err     error
}

func (m *filesRouteDSStub) CreateSession(_ context.Context, _ *auth.RequestAuth, _ int) (string, error) {
	return "", nil
}

func (m *filesRouteDSStub) GetPow(_ context.Context, _ *auth.RequestAuth, _ int) (string, error) {
	return "", nil
}

func (m *filesRouteDSStub) UploadFile(_ context.Context, _ *auth.RequestAuth, req deepseek.UploadFileRequest, _ int) (*deepseek.UploadFileResult, error) {
	m.lastReq = req
	if m.err != nil {
		return nil, m.err
	}
	if m.upload != nil {
		return m.upload, nil
	}
	return &deepseek.UploadFileResult{ID: "file-123", Filename: req.Filename, Bytes: int64(len(req.Data)), Purpose: req.Purpose, Status: "uploaded"}, nil
}

func (m *filesRouteDSStub) CallCompletion(_ context.Context, _ *auth.RequestAuth, _ map[string]any, _ string, _ int) (*http.Response, error) {
	return nil, errors.New("not implemented")
}

func (m *filesRouteDSStub) DeleteSessionForToken(_ context.Context, _ string, _ string) (*deepseek.DeleteSessionResult, error) {
	return &deepseek.DeleteSessionResult{Success: true}, nil
}

func (m *filesRouteDSStub) DeleteAllSessionsForToken(_ context.Context, _ string) error {
	return nil
}

func newMultipartUploadRequest(t *testing.T, purpose string, filename string, data []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if purpose != "" {
		if err := writer.WriteField("purpose", purpose); err != nil {
			t.Fatalf("write purpose failed: %v", err)
		}
	}
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("create form file failed: %v", err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatalf("write file failed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer failed: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/files", &body)
	req.Header.Set("Authorization", "Bearer direct-token")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func TestFilesRouteUploadSuccess(t *testing.T) {
	ds := &filesRouteDSStub{}
	h := &Handler{Store: mockOpenAIConfig{wideInput: true}, Auth: streamStatusAuthStub{}, DS: ds}
	r := chi.NewRouter()
	RegisterRoutes(r, h)

	req := newMultipartUploadRequest(t, "assistants", "notes.txt", []byte("hello world"))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if ds.lastReq.Filename != "notes.txt" {
		t.Fatalf("expected filename notes.txt, got %q", ds.lastReq.Filename)
	}
	if ds.lastReq.Purpose != "assistants" {
		t.Fatalf("expected purpose assistants, got %q", ds.lastReq.Purpose)
	}
	if string(ds.lastReq.Data) != "hello world" {
		t.Fatalf("unexpected uploaded data: %q", string(ds.lastReq.Data))
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response failed: %v body=%s", err, rec.Body.String())
	}
	if out["object"] != "file" {
		t.Fatalf("expected file object, got %#v", out)
	}
	if out["id"] != "file-123" {
		t.Fatalf("expected file id file-123, got %#v", out["id"])
	}
	if out["filename"] != "notes.txt" {
		t.Fatalf("expected filename notes.txt, got %#v", out["filename"])
	}
}

func TestFilesRouteUploadIncludesAccountIDForManagedAccount(t *testing.T) {
	ds := &filesRouteDSStub{}
	h := &Handler{Store: mockOpenAIConfig{wideInput: true}, Auth: managedFilesAuthStub{}, DS: ds}
	r := chi.NewRouter()
	RegisterRoutes(r, h)

	req := newMultipartUploadRequest(t, "assistants", "notes.txt", []byte("hello world"))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response failed: %v body=%s", err, rec.Body.String())
	}
	if out["account_id"] != "acct-123" {
		t.Fatalf("expected account_id acct-123, got %#v", out["account_id"])
	}
}

func TestFilesRouteRejectsNonMultipart(t *testing.T) {
	h := &Handler{Store: mockOpenAIConfig{wideInput: true}, Auth: streamStatusAuthStub{}, DS: &filesRouteDSStub{}}
	r := chi.NewRouter()
	RegisterRoutes(r, h)

	req := httptest.NewRequest(http.MethodPost, "/v1/files", bytes.NewBufferString(`{"purpose":"assistants"}`))
	req.Header.Set("Authorization", "Bearer direct-token")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestFilesRouteRequiresFileField(t *testing.T) {
	h := &Handler{Store: mockOpenAIConfig{wideInput: true}, Auth: streamStatusAuthStub{}, DS: &filesRouteDSStub{}}
	r := chi.NewRouter()
	RegisterRoutes(r, h)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("purpose", "assistants"); err != nil {
		t.Fatalf("write field failed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer failed: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/files", &body)
	req.Header.Set("Authorization", "Bearer direct-token")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}
