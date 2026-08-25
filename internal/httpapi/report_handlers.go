package httpapi

import (
	"net/http"
	"strings"

	"task246-mailalign/internal/domain"
	"task246-mailalign/internal/model"
)

func (s *Server) listSamples(w http.ResponseWriter, r *http.Request) {
	values, err := s.svc.Samples(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, values)
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, model.ErrInvalidArgument)
		return
	}
	value, err := s.svc.Report(r.Context(), id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) verifySnapshot(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, model.ErrInvalidArgument)
		return
	}
	value, err := s.svc.VerifySnapshot(r.Context(), id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) getDiagnosticEvidence(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, model.ErrInvalidArgument)
		return
	}
	value, err := s.svc.Diagnostic(r.Context(), id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"diagnostic_id": id, "status": value.Status, "explanation": value.Explanation, "hop_path": value.HopPath, "spf_trace": value.SPF.Trace, "dkim": value.DKIM})
}

func (s *Server) parentDomains(w http.ResponseWriter, r *http.Request) {
	value, err := domain.Normalize(strings.ToLower(r.PathValue("domain")))
	if err != nil {
		writeErr(w, model.ErrInvalidArgument)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"domain": value, "parents": domain.ParentDomains(value)})
}

func (s *Server) orgDomain(w http.ResponseWriter, r *http.Request) {
	value, err := domain.Normalize(strings.ToLower(r.PathValue("domain")))
	if err != nil {
		writeErr(w, model.ErrInvalidArgument)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"domain": value, "organization": domain.OrgDomain(value)})
}
