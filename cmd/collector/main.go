package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"unified-xdr-platform/collector/api"
	"unified-xdr-platform/collector/engine"
	"unified-xdr-platform/collector/graph"
	"unified-xdr-platform/collector/parser"
	pb "unified-xdr-platform/collector/proto"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v3"
)

// YAML Detection Rule Definitions
type Rule struct {
	ID             string     `yaml:"id"`
	Name           string     `yaml:"name"`
	MitreTechnique string     `yaml:"mitre_technique"`
	Severity       string     `yaml:"severity"`
	Conditions     Conditions `yaml:"conditions"`
}

type Conditions struct {
	EventID          string            `yaml:"event_id"`
	Metadata         map[string]string `yaml:"metadata"`
	MetadataContains map[string]string `yaml:"metadata_contains"`
}

type RuleSet struct {
	Version string `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

type server struct {
	pb.UnimplementedTelemetryServiceServer
	es        *elasticsearch.Client
	graph     *graph.GraphStore
	detEngine *engine.DetectionEngine
	yamlRules []Rule
}

// LoadYamlRules reads and parses dynamic detection rules from disk
func LoadYamlRules(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var ruleSet RuleSet
	err = yaml.Unmarshal(data, &ruleSet)
	if err != nil {
		return nil, err
	}

	return ruleSet.Rules, nil
}

// EvaluateYamlRules checks an event against the loaded rules.yaml definitions
func (s *server) EvaluateYamlRules(event *pb.EventLog) *Rule {
	for _, rule := range s.yamlRules {
		// Check EventID match
		if rule.Conditions.EventID != "" && rule.Conditions.EventID != event.EventId {
			continue
		}

		// Check Exact Metadata Key-Value Matches
		exactMatchFailed := false
		for k, v := range rule.Conditions.Metadata {
			if event.Metadata == nil || event.Metadata[k] != v {
				exactMatchFailed = true
				break
			}
		}
		if exactMatchFailed {
			continue
		}

		// Check Partial Metadata Matches (Substring contains)
		containsMatchFailed := false
		for k, substr := range rule.Conditions.MetadataContains {
			if event.Metadata == nil || !strings.Contains(event.Metadata[k], substr) {
				containsMatchFailed = true
				break
			}
		}
		if containsMatchFailed {
			continue
		}

		// Rule matched
		return &rule
	}
	return nil
}

func (s *server) StreamTelemetry(stream pb.TelemetryService_StreamTelemetryServer) error {
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.StreamResponse{Acknowledged: true})
		}
		if err != nil {
			return err
		}

		log.Printf("[+] Received Event ID: %s | Host: %s | User: %s",
			event.EventId, event.HostName, event.UserName)

		// 1. Evaluate event against dynamic YAML rules
		if matchedRule := s.EvaluateYamlRules(event); matchedRule != nil {
			log.Printf("🚨 [YAML DETECTION ALERT] Rule: %s | ID: %s | MITRE: %s | Severity: %s | Host: %s",
				matchedRule.Name, matchedRule.ID, matchedRule.MitreTechnique, matchedRule.Severity, event.HostName)
		}

		// 2. Parse and enrich event for built-in Detection Engine & Storage
		enrichedDoc := parser.ParseAndEnrich(event)

		go s.indexEventToElasticsearch(enrichedDoc)

		// 3. Evaluate against Detection Engine
		if s.detEngine != nil {
			if alert, triggered := s.detEngine.EvaluateEvent(enrichedDoc); triggered {
				go s.indexAlertToElasticsearch(alert)

				if alert.Severity == "CRITICAL" {
					log.Printf("[🛡️ AUTOMATED RESPONSE] Isolating Host %s due to Critical Incident: %s",
						alert.HostName, alert.Title)
				}
			}
		}

		// 4. Ingest into Graph Database (Neo4j)
		if s.graph != nil {
			go func(e *pb.EventLog) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = s.graph.IngestEvent(ctx, e.EventId, e.HostName, e.UserName, e.SourceIp)
			}(event)
		}
	}
}

func (s *server) indexEventToElasticsearch(enrichedDoc parser.EnrichedEvent) {
	if s.es == nil {
		return
	}

	data, err := json.Marshal(enrichedDoc)
	if err != nil {
		log.Printf("[-] Failed to marshal event: %v", err)
		return
	}

	req := esapi.IndexRequest{
		Index:      "xdr-telemetry-logs",
		DocumentID: "",
		Body:       bytes.NewReader(data),
		Refresh:    "true",
	}

	res, err := req.Do(context.Background(), s.es)
	if err != nil {
		log.Printf("[-] Error indexing to Elasticsearch: %v", err)
		return
	}
	defer res.Body.Close()
}

func (s *server) indexAlertToElasticsearch(alert *engine.Alert) {
	if s.es == nil {
		return
	}

	data, err := json.Marshal(alert)
	if err != nil {
		log.Printf("[-] Failed to marshal alert: %v", err)
		return
	}

	req := esapi.IndexRequest{
		Index:      "xdr-alerts",
		DocumentID: "",
		Body:       bytes.NewReader(data),
		Refresh:    "true",
	}

	res, err := req.Do(context.Background(), s.es)
	if err != nil {
		log.Printf("[-] Error indexing alert: %v", err)
		return
	}
	defer res.Body.Close()

	log.Printf("[🚨] ALERT INDEXED: ID=%s | Severity=%s | Title=%s", alert.AlertID, alert.Severity, alert.Title)
}

func (s *server) ExecuteContainment(ctx context.Context, req *pb.ContainmentRequest) (*pb.ContainmentResponse, error) {
	log.Printf("[!] CONTAINMENT COMMAND RECEIVED: Target Host=%s, Isolate=%t", req.HostName, req.Isolate)
	return &pb.ContainmentResponse{
		Success: true,
		Message: fmt.Sprintf("Containment signal delivered to %s", req.HostName),
	}, nil
}

func main() {
	// 0. Load Dynamic YAML Rules
	yamlRules, err := LoadYamlRules("rules.yaml")
	if err != nil {
		log.Printf("[!] Warning: Could not load rules.yaml (%v). Running without YAML detection engine.", err)
	} else {
		log.Printf("[+] Successfully loaded %d detection rules from rules.yaml", len(yamlRules))
	}

	// 1. Elasticsearch Connection
	esCfg := elasticsearch.Config{Addresses: []string{"http://127.0.0.1:9200"}}
	esClient, err := elasticsearch.NewClient(esCfg)
	if err != nil {
		log.Fatalf("Error creating Elasticsearch client: %v", err)
	}

	res, err := esClient.Info()
	if err != nil {
		log.Fatalf("Error connecting to Elasticsearch: %v", err)
	}
	defer res.Body.Close()
	log.Println("[+] Successfully connected to Elasticsearch cluster at http://127.0.0.1:9200")

	// 2. Neo4j Connection
	graphStore, err := graph.NewGraphStore("bolt://127.0.0.1:7687", "neo4j", "password123")
	if err != nil {
		log.Printf("[!] Warning: Neo4j connection failed (%v). Continuing without Graph Store.", err)
	} else {
		defer graphStore.Close(context.Background())
	}

	// 3. Detection Engine
	detEngine := engine.NewDetectionEngine()
	log.Println("[+] Real-Time Correlation & Detection Engine initialized.")

	// 4. Start REST API Server in a background goroutine
	apiServer, err := api.NewAPIServer(esClient, "127.0.0.1:50051")
	if err != nil {
		log.Fatalf("Failed to initialize API Server: %v", err)
	}
	go apiServer.Start(":8080")

	// 5. Start gRPC Server
	port := ":50051"
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Failed to listen on port %s: %v", port, err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterTelemetryServiceServer(grpcServer, &server{
		es:        esClient,
		graph:     graphStore,
		detEngine: detEngine,
		yamlRules: yamlRules,
	})

	log.Printf("[*] Unified XDR Ingestion & Response Server listening on port %s...", port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve gRPC: %v", err)
	}
}
