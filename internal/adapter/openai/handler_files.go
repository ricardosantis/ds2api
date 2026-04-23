package openai

import (
	"io"
	"net/http"
	"strings"
	"time"

	"ds2api/internal/auth"
	"ds2api/internal/deepseek"
)

const openAIUploadMaxMemory = 32 << 20

func (h *Handler) UploadFile(w http.ResponseWriter, r *http.Request) {
	a, err := h.Auth.Determine(r)
	if err != nil {
		status := http.StatusUnauthorized
		detail := err.Error()
		if err == auth.ErrNoAccount {
			status = http.StatusTooManyRequests
		}
		writeOpenAIError(w, status, detail)
		return
	}
	defer h.Auth.Release(a)
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type"))), "multipart/form-data") {
		writeOpenAIError(w, http.StatusBadRequest, "content-type must be multipart/form-data")
		return
	}
	// Enforce a hard cap on the total request body size to prevent OOM
	r.Body = http.MaxBytesReader(w, r.Body, openAIUploadMaxSize)
	if err := r.ParseMultipartForm(openAIUploadMaxMemory); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "too large") {
			writeOpenAIError(w, http.StatusRequestEntityTooLarge, "file size exceeds limit")
			return
		}
		writeOpenAIError(w, http.StatusBadRequest, "invalid multipart form")
		return
	}
	if r.MultipartForm != nil {
		defer func() { _ = r.MultipartForm.RemoveAll() }()
	}
	r = r.WithContext(auth.WithAuth(r.Context(), a))
	file, header, err := r.FormFile("file")
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(file)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "failed to read uploaded file")
		return
	}
	contentType := strings.TrimSpace(header.Header.Get("Content-Type"))
	if contentType == "" && len(data) > 0 {
		contentType = http.DetectContentType(data)
	}
	result, err := h.DS.UploadFile(r.Context(), a, deepseek.UploadFileRequest{
		Filename:    header.Filename,
		ContentType: contentType,
		Purpose:     strings.TrimSpace(r.FormValue("purpose")),
		Data:        data,
	}, 3)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "Failed to upload file.")
		return
	}
	if result != nil && result.AccountID == "" {
		result.AccountID = a.AccountID
	}
	writeJSON(w, http.StatusOK, buildOpenAIFileObject(result))
}

func buildOpenAIFileObject(result *deepseek.UploadFileResult) map[string]any {
	if result == nil {
		obj := map[string]any{
			"id":             "",
			"object":         "file",
			"bytes":          0,
			"created_at":     time.Now().Unix(),
			"filename":       "",
			"purpose":        "",
			"status":         "uploaded",
			"status_details": nil,
		}
		return obj
	}
	obj := map[string]any{
		"id":             result.ID,
		"object":         "file",
		"bytes":          result.Bytes,
		"created_at":     time.Now().Unix(),
		"filename":       result.Filename,
		"purpose":        result.Purpose,
		"status":         result.Status,
		"status_details": nil,
	}
	if result.AccountID != "" {
		obj["account_id"] = result.AccountID
	}
	return obj
}
