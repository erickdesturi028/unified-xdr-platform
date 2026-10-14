package graph

import (
	"context"
	"fmt"
	"log"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type GraphStore struct {
	driver neo4j.DriverWithContext
}

// NewGraphStore initializes the Neo4j connection pool
func NewGraphStore(uri, user, password string) (*GraphStore, error) {
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, password, ""))
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	err = driver.VerifyConnectivity(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to verify Neo4j connectivity: %w", err)
	}

	log.Println("[+] Successfully connected to Neo4j Graph Database at", uri)
	return &GraphStore{driver: driver}, nil
}

// Close gracefully closes the Neo4j driver connection
func (g *GraphStore) Close(ctx context.Context) {
	if g.driver != nil {
		g.driver.Close(ctx)
	}
}

// IngestEvent maps telemetry events into Graph Nodes and Relationships
func (g *GraphStore) IngestEvent(ctx context.Context, eventID string, hostName string, userName string, sourceIP string) error {
	session := g.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	cypherQuery := `
		MERGE (u:User {name: $userName})
		MERGE (h:Host {name: $hostName})
		MERGE (ip:IP {address: $sourceIP})

		MERGE (u)-[r1:AUTHENTICATED_TO {event_id: $eventID}]->(h)
		MERGE (ip)-[r2:ORIGINATED_FROM]->(u)
	`

	params := map[string]any{
		"userName": userName,
		"hostName": hostName,
		"sourceIP": sourceIP,
		"eventID":  eventID,
	}

	_, err := session.Run(ctx, cypherQuery, params)
	if err != nil {
		log.Printf("[-] Failed to create Neo4j relationships: %v", err)
		return err
	}

	log.Printf("[🕸️] Neo4j Graph Updated: (%s)-[AUTHENTICATED_TO]->(%s)", userName, hostName)
	return nil
}
