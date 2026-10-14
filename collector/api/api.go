package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	pb "unified-xdr-platform/collector/proto"

	"github.com/elastic/go-elasticsearch/v8"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type APIServer struct {
	es       *elasticsearch.Client
	grpcConn *grpc.ClientConn
}

func NewAPIServer(es *elasticsearch.Client, grpcTarget string) (*APIServer, error) {
	conn, err := grpc.Dial(grpcTarget, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return &APIServer{
		es:       es,
		grpcConn: conn,
	}, nil
}

// enableCORS adds headers to allow browser requests from any local frontend
func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func (a *APIServer) Start(port string) {
	mux := http.NewServeMux()

	// Core Endpoints
	mux.HandleFunc("/api/v1/alerts", enableCORS(a.handleGetAlerts))
	mux.HandleFunc("/api/v1/logs", enableCORS(a.handleGetLogs))
	mux.HandleFunc("/api/v1/containment", enableCORS(a.handleContainment))

	// Option 5: Threat Hunting API Endpoints
	mux.HandleFunc("/api/v1/hunt", enableCORS(a.handleHuntQuery))
	mux.HandleFunc("/api/v1/hunt/powershell", enableCORS(a.handleHuntPowerShell))
	mux.HandleFunc("/api/v1/hunt/logons", enableCORS(a.handleHuntLogons))
	mux.HandleFunc("/api/v1/hunt/processes", enableCORS(a.handleHuntProcesses))
	mux.HandleFunc("/api/v1/hunt/mitre", enableCORS(a.handleHuntMitre))

	log.Printf("[🌐] REST API Server listening on http://127.0.0.1%s", port)
	if err := http.ListenAndServe(port, mux); err != nil {
		log.Fatalf("API Server failed: %v", err)
	}
}

// GET /api/v1/alerts
func (a *APIServer) handleGetAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := `{"query": {"match_all": {}}, "sort": [{"timestamp": {"order": "desc"}}], "size": 50}`
	a.executeESSearch(w, "xdr-alerts", query)
}

// GET /api/v1/logs
func (a *APIServer) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := `{"query": {"match_all": {}}, "sort": [{"timestamp": {"order": "desc"}}], "size": 50}`
	a.executeESSearch(w, "xdr-telemetry-logs", query)
}

// Option 5: Threat Hunting — Query Rare/Encoded PowerShell Executions
// GET /api/v1/hunt/powershell
func (a *APIServer) handleHuntPowerShell(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := `{
		"query": {
			"bool": {
				"should": [
					{"match_phrase": {"metadata.ProcessName": "powershell.exe"}},
					{"match_phrase": {"metadata.ScriptBlockText": "Invoke-Mimikatz"}},
					{"match_phrase": {"metadata.ScriptBlockText": "EncodedCommand"}},
					{"match_phrase": {"metadata.ParentProcess": "wsmprovhost.exe"}}
				],
				"minimum_should_match": 1
			}
		},
		"sort": [{"timestamp": {"order": "desc"}}],
		"size": 50
	}`
	a.executeESSearch(w, "xdr-telemetry-logs", query)
}

// Option 5: Threat Hunting — Query Suspicious Logons / Active Directory Activity
// GET /api/v1/hunt/logons
func (a *APIServer) handleHuntLogons(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := `{
		"query": {
			"terms": {
				"event_id": ["4624", "4769", "4625"]
			}
		},
		"sort": [{"timestamp": {"order": "desc"}}],
		"size": 50
	}`
	a.executeESSearch(w, "xdr-telemetry-logs", query)
}

// Option 5: Threat Hunting — Query Ransomware & Process Anomalies (e.g. vssadmin)
// GET /api/v1/hunt/processes
func (a *APIServer) handleHuntProcesses(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := `{
		"query": {
			"bool": {
				"should": [
					{"match_phrase": {"metadata.ProcessName": "vssadmin.exe"}},
					{"match_phrase": {"metadata.CommandLine": "delete shadows"}},
					{"match_phrase": {"metadata.ParentProcess": "unknown_ransomware.exe"}}
				],
				"minimum_should_match": 1
			}
		},
		"sort": [{"timestamp": {"order": "desc"}}],
		"size": 50
	}`
	a.executeESSearch(w, "xdr-telemetry-logs", query)
}

// Option 5: Threat Hunting — Query by MITRE Technique ID
// GET /api/v1/hunt/mitre?technique=T1558.003
func (a *APIServer) handleHuntMitre(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	technique := r.URL.Query().Get("technique")
	if technique == "" {
		http.Error(w, `{"error": "Query parameter 'technique' is required (e.g., ?technique=T1558.003)"}`, http.StatusBadRequest)
		return
	}

	query := fmt.Sprintf(`{
		"query": {
			"match": {
				"metadata.MitreTechnique": "%s"
			}
		},
		"sort": [{"timestamp": {"order": "desc"}}],
		"size": 50
	}`, technique)

	a.executeESSearch(w, "xdr-telemetry-logs", query)
}

// Option 5: Generic Keyword Search across Telemetry Logs
// GET /api/v1/hunt?q=keyword
func (a *APIServer) handleHuntQuery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	searchTerm := r.URL.Query().Get("q")
	var query string
	if searchTerm == "" {
		query = `{"query": {"match_all": {}}, "sort": [{"timestamp": {"order": "desc"}}], "size": 50}`
	} else {
		query = fmt.Sprintf(`{
			"query": {
				"query_string": {
					"query": "*%s*"
				}
			},
			"sort": [{"timestamp": {"order": "desc"}}],
			"size": 50
		}`, searchTerm)
	}

	a.executeESSearch(w, "xdr-telemetry-logs", query)
}

// POST /api/v1/containment
type ContainmentReqBody struct {
	HostName string `json:"host_name"`
	Isolate  bool   `json:"isolate"`
}

func (a *APIServer) handleContainment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqBody ContainmentReqBody
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	client := pb.NewTelemetryServiceClient(a.grpcConn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.ExecuteContainment(ctx, &pb.ContainmentRequest{
		HostName: reqBody.HostName,
		Isolate:  reqBody.Isolate,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp)
}

// Helper to execute Elasticsearch queries and write HTTP response
func (a *APIServer) executeESSearch(w http.ResponseWriter, index string, query string) {
	if a.es == nil {
		http.Error(w, `{"error": "Elasticsearch client not configured"}`, http.StatusInternalServerError)
		return
	}

	res, err := a.es.Search(
		a.es.Search.WithIndex(index),
		a.es.Search.WithBody(bytes.NewReader([]byte(query))),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}
