package httpapi

import (
	"net/http"

	"task246-mailalign/internal/model"
)

func (s *Server) saveSPF(w http.ResponseWriter, r *http.Request) {
	var value model.SPFRecord
	if err := decode(r, &value); err != nil {
		writeErr(w, model.ErrInvalidArgument)
		return
	}
	created, err := s.svc.SaveSPF(r.Context(), value)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) listSPF(w http.ResponseWriter, r *http.Request) {
	values, err := s.svc.Store().SPF(r.Context(), "")
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, values)
}

func (s *Server) saveDKIM(w http.ResponseWriter, r *http.Request) {
	var value model.DKIMRecord
	if err := decode(r, &value); err != nil {
		writeErr(w, model.ErrInvalidArgument)
		return
	}
	created, err := s.svc.SaveDKIM(r.Context(), value)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) listDKIM(w http.ResponseWriter, r *http.Request) {
	values, err := s.svc.Store().DKIM(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, values)
}
