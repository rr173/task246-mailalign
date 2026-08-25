package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"task246-mailalign/internal/model"
)

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeErr(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, model.ErrInvalidArgument):
		status = http.StatusBadRequest
	case errors.Is(err, model.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, model.ErrConflict):
		status = http.StatusConflict
	case errors.Is(err, model.ErrInvalidState), errors.Is(err, model.ErrImmutable):
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func decode(r *http.Request, target any) error { return json.NewDecoder(r.Body).Decode(target) }
