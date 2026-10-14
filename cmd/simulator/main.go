package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"time"

	pb "unified-xdr-platform/collector/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var targetHosts = []string{"WORKSTATION-01", "WORKSTATION-02", "DC01.corp.local", "FINANCE-SERVER"}
var users = []string{"j.doe", "admin_user", "sql_service", "a.smith", "SYSTEM"}

func main() {
	rand.Seed(time.Now().UnixNano())

	// Connect to gRPC Collector Server
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Did not connect to gRPC server: %v", err)
	}
	defer conn.Close()

	client := pb.NewTelemetryServiceClient(conn)

	log.Println("[*] Starting continuous attack & telemetry simulation to gRPC Collector...")

	for {
		// Establish gRPC stream for a batch of events
		stream, err := client.StreamTelemetry(context.Background())
		if err != nil {
			log.Printf("⚠️ Error creating stream: %v. Retrying in 3 seconds...", err)
			time.Sleep(3 * time.Second)
			continue
		}

		// Generate a batch of 5 events per stream burst
		for i := 0; i < 5; i++ {
			scenario := rand.Intn(10)
			var event *pb.EventLog

			switch scenario {
			case 0, 1:
				// Scenario 1: AD Kerberoasting Attack (MITRE T1558.003)
				event = generateKerberoastEvent()
			case 2, 3:
				// Scenario 2: Ransomware Behavior & Shadow Copy Deletion (MITRE T1486)
				event = generateRansomwareEvent()
			case 4, 5:
				// Scenario 3: Lateral Movement via Remote PowerShell (MITRE T1021.006)
				event = generateLateralMovementEvent()
			default:
				// Benign Host Activity
				event = generateBenignEvent()
			}

			if err := stream.Send(event); err != nil {
				log.Printf("❌ Failed to send event %s: %v", event.EventId, err)
				break
			}

			log.Printf("[>] Sent Event ID: %-5s | Host: %-16s | User: %-12s", event.EventId, event.HostName, event.UserName)
			time.Sleep(1 * time.Second)
		}

		// Close stream and receive acknowledgment from collector server
		reply, err := stream.CloseAndRecv()
		if err != nil {
			log.Printf("⚠️ Stream close error: %v", err)
		} else {
			log.Printf("[✓] Stream acknowledged by collector: %t", reply.Acknowledged)
		}

		time.Sleep(2 * time.Second)
	}
}

// Attack Vector 1: Active Directory Kerberoasting Attack (T1558.003)
func generateKerberoastEvent() *pb.EventLog {
	user := users[rand.Intn(len(users))]
	return &pb.EventLog{
		EventId:   "4769", // Kerberos TGS Ticket Request
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		HostName:  "DC01.corp.local",
		UserName:  user,
		SourceIp:  fmt.Sprintf("192.168.1.%d", rand.Intn(100)+100),
		Metadata: map[string]string{
			"ServiceName":          "MSSQLSvc/db01.corp.local:1433",
			"TicketOptions":        "0x40810000",
			"TicketEncryptionType": "0x17", // RC4-HMAC (Weak/Kerberoastable)
			"MitreTechnique":       "T1558.003",
			"Severity":             "CRITICAL",
			"EventType":            "KERBEROASTING_ATTEMPT",
		},
	}
}

// Attack Vector 2: Ransomware Behavior (T1486)
func generateRansomwareEvent() *pb.EventLog {
	host := targetHosts[rand.Intn(len(targetHosts))]
	return &pb.EventLog{
		EventId:   "4104", // PowerShell / Process Execution
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		HostName:  host,
		UserName:  "a.smith",
		SourceIp:  "127.0.0.1",
		Metadata: map[string]string{
			"ProcessName":     "vssadmin.exe",
			"CommandLine":     "vssadmin.exe delete shadows /all /quiet",
			"ParentProcess":   "unknown_ransomware.exe",
			"ScriptBlockText": "vssadmin.exe delete shadows /all /quiet",
			"MitreTechnique":  "T1486",
			"Severity":        "CRITICAL",
			"EventType":       "RANSOMWARE_BEHAVIOR",
		},
	}
}

// Attack Vector 3: Lateral Movement via Remote Encoded PowerShell (T1021.006)
func generateLateralMovementEvent() *pb.EventLog {
	host := targetHosts[rand.Intn(len(targetHosts))]
	return &pb.EventLog{
		EventId:   "4104", // Script Block Logging
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		HostName:  host,
		UserName:  "admin_user",
		SourceIp:  "10.0.0.45",
		Metadata: map[string]string{
			"ProcessName":     "powershell.exe",
			"ParentProcess":   "wsmprovhost.exe",
			"ScriptBlockText": "Invoke-Mimikatz -DumpCreds -EncodedCommand JABzAD0ATg...",
			"MitreTechnique":  "T1021.006",
			"Severity":        "HIGH",
			"EventType":       "LATERAL_MOVEMENT",
		},
	}
}

// Standard Benign Event (Logon or Process execution)
func generateBenignEvent() *pb.EventLog {
	host := targetHosts[rand.Intn(len(targetHosts))]
	user := users[rand.Intn(len(users))]
	return &pb.EventLog{
		EventId:   "4624", // Successful Logon
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		HostName:  host,
		UserName:  user,
		SourceIp:  "192.168.1.50",
		Metadata: map[string]string{
			"LogonType":      "3", // Network Logon
			"MitreTechnique": "N/A",
			"Severity":       "INFO",
			"EventType":      "USER_LOGON",
		},
	}
}
