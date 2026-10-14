package engine

import (
	"log"
	"time"

	"unified-xdr-platform/collector/parser"
)

// Alert represents an actionable security incident detected by the engine
type Alert struct {
	AlertID        string    `json:"alert_id"`
	Title          string    `json:"title"`
	Severity       string    `json:"severity"`
	MitreTechnique string    `json:"mitre_technique"`
	HostName       string    `json:"host_name"`
	UserName       string    `json:"user_name"`
	Description    string    `json:"description"`
	Timestamp      time.Time `json:"timestamp"`
}

// DetectionEngine evaluates incoming enriched events against security detection rules
type DetectionEngine struct{}

func NewDetectionEngine() *DetectionEngine {
	return &DetectionEngine{}
}

// EvaluateEvent checks an enriched event against correlation logic
func (de *DetectionEngine) EvaluateEvent(event parser.EnrichedEvent) (*Alert, bool) {
	// Rule 1: Kerberoasting Attack Detection
	if event.EventID == "4769" && event.Severity == "HIGH" {
		alert := &Alert{
			AlertID:        "ALT-KERB-001",
			Title:          "Potential Kerberoasting Attack Detected",
			Severity:       "CRITICAL",
			MitreTechnique: "T1558.003 (Kerberoasting)",
			HostName:       event.HostName,
			UserName:       event.UserName,
			Description:    "High volume TGS request with RC4 encryption (0x17) detected from user: " + event.UserName,
			Timestamp:      time.Now(),
		}
		log.Printf("[🚨 ALERT GENERATED] %s on Host: %s | User: %s", alert.Title, alert.HostName, alert.UserName)
		return alert, true
	}

	// Rule 2: Suspicious PowerShell Execution
	if event.EventID == "4104" && event.Severity == "HIGH" {
		alert := &Alert{
			AlertID:        "ALT-PS-002",
			Title:          "Suspicious PowerShell Script Block Executed",
			Severity:       "HIGH",
			MitreTechnique: "T1059.001 (PowerShell)",
			HostName:       event.HostName,
			UserName:       event.UserName,
			Description:    "Script block execution detected on target machine: " + event.HostName,
			Timestamp:      time.Now(),
		}
		log.Printf("[🚨 ALERT GENERATED] %s on Host: %s", alert.Title, alert.HostName)
		return alert, true
	}

	return nil, false
}
