package parser

import (
	pb "unified-xdr-platform/collector/proto"
)

// EnrichedEvent represents the structured event ready for Elasticsearch & Detection Engine
type EnrichedEvent struct {
	EventID        string            `json:"event_id"`
	Timestamp      string            `json:"timestamp"`
	HostName       string            `json:"host_name"`
	UserName       string            `json:"user_name"`
	SourceIP       string            `json:"source_ip"`
	Metadata       map[string]string `json:"metadata"`
	Category       string            `json:"category"`
	Severity       string            `json:"severity"`
	MitreTechnique string            `json:"mitre_technique"`
}

// ParseAndEnrich evaluates raw protobuf events and attaches security taxonomy
func ParseAndEnrich(event *pb.EventLog) EnrichedEvent {
	enriched := EnrichedEvent{
		EventID:        event.EventId,
		Timestamp:      event.Timestamp,
		HostName:       event.HostName,
		UserName:       event.UserName,
		SourceIP:       event.SourceIp,
		Metadata:       event.Metadata,
		Category:       "General",
		Severity:       "INFORMATIONAL",
		MitreTechnique: "N/A",
	}

	// Active Directory / Endpoint Logic Rules
	switch event.EventId {
	case "4769": // A Kerberos ticket-granting service (TGS) request was requested
		enriched.Category = "Active Directory / Identity"
		// Check for RC4 encryption (0x17) which is commonly used in Kerberoasting attacks
		if encType, ok := event.Metadata["TicketEncryptionType"]; ok && encType == "0x17" {
			enriched.Severity = "HIGH"
			enriched.MitreTechnique = "T1558.003 (Kerberoasting)"
		} else {
			enriched.Severity = "LOW"
		}

	case "4624": // Successful Logon
		enriched.Category = "Authentication"
		// Check for Remote Interactive logon (Type 10 = RDP)
		if logonType, ok := event.Metadata["LogonType"]; ok && logonType == "10" {
			enriched.Severity = "MEDIUM"
			enriched.MitreTechnique = "T1078 (Valid Accounts - RDP)"
		}

	case "4104": // PowerShell Script Block Execution
		enriched.Category = "Process Execution"
		enriched.Severity = "HIGH"
		enriched.MitreTechnique = "T1059.001 (PowerShell Execution)"
	}

	return enriched
}
