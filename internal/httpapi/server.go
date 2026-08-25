package httpapi

import (
	"net/http"
	"strconv"

	"task246-mailalign/internal/service"
)

type Server struct {
	svc *service.Service
	mux *http.ServeMux
}

func New(svc *service.Service) *Server {
	server := &Server{svc: svc, mux: http.NewServeMux()}
	server.routes()
	return server
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/self-check", s.selfCheck)
	s.mux.HandleFunc("POST /api/samples", s.createSample)
	s.mux.HandleFunc("GET /api/samples", s.listSamples)
	s.mux.HandleFunc("GET /api/samples/{id}", s.getSample)
	s.mux.HandleFunc("POST /api/samples/{id}/hops", s.addHop)
	s.mux.HandleFunc("GET /api/samples/{id}/hops", s.listHops)
	s.mux.HandleFunc("POST /api/samples/{id}/analyze", s.analyze)
	s.mux.HandleFunc("GET /api/samples/{id}/diagnostic", s.diagnostic)
	s.mux.HandleFunc("GET /api/samples/{id}/report", s.report)
	s.mux.HandleFunc("POST /api/samples/{id}/snapshots", s.publishSnapshot)
	s.mux.HandleFunc("POST /api/hops/{id}/trust", s.trustHop)
	s.mux.HandleFunc("POST /api/spf-records", s.saveSPF)
	s.mux.HandleFunc("GET /api/spf-records", s.listSPF)
	s.mux.HandleFunc("POST /api/dkim-records", s.saveDKIM)
	s.mux.HandleFunc("GET /api/dkim-records", s.listDKIM)
	s.mux.HandleFunc("GET /api/snapshots/{id}", s.getSnapshot)
	s.mux.HandleFunc("GET /api/snapshots/{id}/verify", s.verifySnapshot)
	s.mux.HandleFunc("GET /api/diagnostics/{id}/evidence", s.getDiagnosticEvidence)
	s.mux.HandleFunc("GET /api/domains/{domain}/parents", s.parentDomains)
	s.mux.HandleFunc("GET /api/domains/{domain}/org", s.orgDomain)
}

func pathID(r *http.Request) (int64, error) { return strconv.ParseInt(r.PathValue("id"), 10, 64) }
