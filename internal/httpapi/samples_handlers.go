package httpapi

import (
	"net/http"

	"task246-mailalign/internal/model"
)

func (s *Server) selfCheck(w http.ResponseWriter, r *http.Request) {
	value, err := s.svc.SelfCheck(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) createSample(w http.ResponseWriter, r *http.Request) {
	var value model.MessageSample
	if err := decode(r, &value); err != nil {
		writeErr(w, model.ErrInvalidArgument)
		return
	}
	created, duplicate, err := s.svc.CreateSample(r.Context(), value)
	if err != nil {
		writeErr(w, err)
		return
	}
	status := http.StatusCreated
	if duplicate {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"duplicate": duplicate, "sample": created})
}

func (s *Server) getSample(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, model.ErrInvalidArgument)
		return
	}
	value, err := s.svc.Sample(r.Context(), id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) addHop(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, model.ErrInvalidArgument)
		return
	}
	var value model.Hop
	if err := decode(r, &value); err != nil {
		writeErr(w, model.ErrInvalidArgument)
		return
	}
	value.SampleID = id
	created, err := s.svc.AddHop(r.Context(), value)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) listHops(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, model.ErrInvalidArgument)
		return
	}
	values, err := s.svc.Hops(r.Context(), id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, values)
}

func (s *Server) analyze(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, model.ErrInvalidArgument)
		return
	}
	var request struct {
		DKIMDomain string `json:"dkim_domain"`
		Selector   string `json:"selector"`
	}
	if err := decode(r, &request); err != nil {
		writeErr(w, model.ErrInvalidArgument)
		return
	}
	value, err := s.svc.Analyze(r.Context(), id, request.DKIMDomain, request.Selector)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) diagnostic(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, model.ErrInvalidArgument)
		return
	}
	value, err := s.svc.DiagnosticForSample(r.Context(), id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) trustHop(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, model.ErrInvalidArgument)
		return
	}
	if err := s.svc.TrustHop(r.Context(), id); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": model.HopTrusted})
}
