// Command mailalign exposes the SPF/DKIM alignment diagnosis service.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"task246-mailalign/internal/dkim"
	"task246-mailalign/internal/httpapi"
	"task246-mailalign/internal/model"
	"task246-mailalign/internal/service"
	"task246-mailalign/internal/store"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	dbPath := flag.String("db", "mailalign.db", "SQLite database path")
	smoke := flag.Bool("smoke-test", false, "run deterministic end-to-end self test")
	flag.Parse()
	if *smoke {
		if err := runSmoke(); err != nil {
			log.Fatalf("smoke test failed: %v", err)
		}
		fmt.Println("SMOKE TEST PASSED")
		return
	}
	repository, err := store.Open(*dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer repository.Close()
	svc := service.New(repository)
	if err := svc.Recover(context.Background()); err != nil {
		log.Fatal(err)
	}
	log.Printf("mailalign listening on %s (db=%s)", *addr, *dbPath)
	if err := http.ListenAndServe(*addr, httpapi.New(svc).Handler()); err != nil {
		log.Fatal(err)
	}
}

func runSmoke() error {
	dir, err := os.MkdirTemp("", "mailalign-smoke-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	dbPath := filepath.Join(dir, "mailalign.db")
	ctx := context.Background()
	repository, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	svc := service.New(repository)
	body := "Date: Tue\r\nSubject: sample\r\n\r\nhello\r\n"
	spfRecord, err := svc.SaveSPF(ctx, model.SPFRecord{Domain: "mx.example.com", Version: 1, Mechanisms: []string{"ip4:203.0.113.0/24", "-all"}})
	if err != nil {
		return err
	}
	if spfRecord.Domain != "mx.example.com" {
		return fmt.Errorf("SPF domain not normalized")
	}
	if _, err = svc.SaveDKIM(ctx, model.DKIMRecord{Domain: "signed.example.com", Selector: "s1", Version: 1, BodySHA: dkim.BodySHA(body)}); err != nil {
		return err
	}
	sample, _, err := svc.CreateSample(ctx, model.MessageSample{VisibleFrom: "alice@corp.example.com", ReturnPath: "bounce@mx.example.com", RecipientIP: "203.0.113.7", Body: body})
	if err != nil {
		return err
	}
	firstHop, err := svc.AddHop(ctx, model.Hop{SampleID: sample.ID, Sequence: 1, FromDomain: "edge.example.net", ByDomain: "mx.example.com", ClientIP: "203.0.113.7"})
	if err != nil {
		return err
	}
	if _, err = svc.AddHop(ctx, model.Hop{SampleID: sample.ID, Sequence: 2, FromDomain: "mx.example.com", ByDomain: "relay.example.com", ClientIP: "203.0.113.7"}); err != nil {
		return err
	}
	if err = svc.TrustHop(ctx, firstHop.ID); err != nil {
		return err
	}
	diagnostic, err := svc.Analyze(ctx, sample.ID, "signed.example.com", "s1")
	if err != nil {
		return err
	}
	if !diagnostic.RelaxedAligned || diagnostic.StrictAligned || diagnostic.DKIM.Status != "pass" {
		return fmt.Errorf("unexpected relaxed alignment: %+v", diagnostic)
	}
	snapshot, err := svc.PublishSnapshot(ctx, sample.ID)
	if err != nil {
		return err
	}
	if snapshot.Status != model.SnapshotPublished || snapshot.ContentSHA == "" {
		return fmt.Errorf("snapshot not published")
	}
	bad, _, err := svc.CreateSample(ctx, model.MessageSample{VisibleFrom: "alice@corp.example.com", ReturnPath: "bounce@mx.example.com", RecipientIP: "203.0.113.7", Body: body + "tampered"})
	if err != nil {
		return err
	}
	if _, err = svc.Analyze(ctx, bad.ID, "signed.example.com", "s1"); err != nil {
		return err
	}
	badDiagnostic, err := svc.DiagnosticForSample(ctx, bad.ID)
	if err != nil {
		return err
	}
	if badDiagnostic.DKIM.Status != "fail" {
		return fmt.Errorf("expected tampered body to fail DKIM")
	}
	if err = repository.Close(); err != nil {
		return err
	}
	reopened, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer reopened.Close()
	svc2 := service.New(reopened)
	if err = svc2.Recover(ctx); err != nil {
		return err
	}
	restored, err := svc2.Snapshot(ctx, snapshot.ID)
	if err != nil {
		return err
	}
	if restored.Status != model.SnapshotPublished || restored.ContentSHA != snapshot.ContentSHA {
		return fmt.Errorf("snapshot recovery mismatch")
	}
	return nil
}
