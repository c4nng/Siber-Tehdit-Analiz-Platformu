package handlers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	WAZUH_URL  = "https://localhost:9200"
	WAZUH_USER = "admin"
	WAZUH_PASS = "SecretPassword"

	OPENCTI_URL   = "http://localhost:8080/graphql"
	OPENCTI_TOKEN = "9a8b501e-712a-4e61-b1c9-1197d235f683"
)

var httpClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	Timeout: 10 * time.Second,
}

type IOCResult struct {
	Matched     uint8
	EntityType  string
	Score       uint8
	Description string
	ThreatActor string
	MitreTech   string
	TLPLevel    string
	CVE         string
}

func getLastTimestamp() string {
	db, err := getDB()
	if err != nil {
		return "2026-04-06T00:00:00.000Z"
	}
	defer db.Close()

	var count uint64
	row := db.QueryRow(context.Background(), "SELECT count() FROM security.wazuh_events")
	row.Scan(&count)
	if count == 0 {
		return "2026-04-06T00:00:00.000Z"
	}

	var ts time.Time
	row = db.QueryRow(context.Background(), "SELECT max(ts) FROM security.wazuh_events")
	row.Scan(&ts)
	return ts.UTC().Format("2006-01-02T15:04:05.000Z")
}

func fetchAlerts(since string) ([]map[string]interface{}, error) {
	payload := map[string]interface{}{
		"size": 1000,
		"sort": []map[string]interface{}{{"timestamp": map[string]string{"order": "asc"}}},
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]string{"gt": since},
			},
		},
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("GET", WAZUH_URL+"/wazuh-alerts-*/_search", bytes.NewBuffer(body))
	req.SetBasicAuth(WAZUH_USER, WAZUH_PASS)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	hits, _ := result["hits"].(map[string]interface{})
	items, _ := hits["hits"].([]interface{})

	alerts := []map[string]interface{}{}
	for _, item := range items {
		if m, ok := item.(map[string]interface{}); ok {
			if src, ok := m["_source"].(map[string]interface{}); ok {
				alerts = append(alerts, src)
			}
		}
	}
	return alerts, nil
}

func checkIOC(value string) IOCResult {
	if value == "" {
		return IOCResult{}
	}

	log.Printf("[IOC] Sorgulanıyor: %s", value)

	payload := map[string]interface{}{
		"query": fmt.Sprintf(`{
			stixCyberObservables(search: "%s") {
				edges {
					node {
						entity_type
						observable_value
						x_opencti_score
						x_opencti_description
					}
				}
			}
		}`, value),
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", OPENCTI_URL, bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+OPENCTI_TOKEN)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("[IOC] HTTP hatası: %v", err)
		return IOCResult{}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	preview := respBody
	if len(preview) > 200 {
		preview = preview[:200]
	}
	log.Printf("[IOC] OpenCTI yanıtı: %s", string(preview))

	var result map[string]interface{}
	json.Unmarshal(respBody, &result)

	data, _ := result["data"].(map[string]interface{})
	obs, _ := data["stixCyberObservables"].(map[string]interface{})
	edges, _ := obs["edges"].([]interface{})

	if len(edges) == 0 {
		return IOCResult{}
	}

	log.Printf("[IOC] EŞLEŞME BULUNDU: %s", value)

	edge, _ := edges[0].(map[string]interface{})
	node, _ := edge["node"].(map[string]interface{})

	ioc := IOCResult{Matched: 1}
	ioc.EntityType, _  = node["entity_type"].(string)
	ioc.Description, _ = node["x_opencti_description"].(string)

	if score, ok := node["x_opencti_score"].(float64); ok {
		ioc.Score = uint8(score)
	}

	return ioc
}

func getString(m map[string]interface{}, keys ...string) string {
	current := m
	for i, key := range keys {
		if i == len(keys)-1 {
			if v, ok := current[key].(string); ok {
				return v
			}
			return ""
		}
		if next, ok := current[key].(map[string]interface{}); ok {
			current = next
		} else {
			return ""
		}
	}
	return ""
}

func getUint8(m map[string]interface{}, keys ...string) uint8 {
	current := m
	for i, key := range keys {
		if i == len(keys)-1 {
			switch v := current[key].(type) {
			case float64:
				return uint8(v)
			case int:
				return uint8(v)
			}
			return 0
		}
		if next, ok := current[key].(map[string]interface{}); ok {
			current = next
		} else {
			return 0
		}
	}
	return 0
}

func getUint32(m map[string]interface{}, keys ...string) uint32 {
	current := m
	for i, key := range keys {
		if i == len(keys)-1 {
			switch v := current[key].(type) {
			case float64:
				return uint32(v)
			case int:
				return uint32(v)
			case string:
				var n uint32
				fmt.Sscanf(v, "%d", &n)
				return n
			}
			return 0
		}
		if next, ok := current[key].(map[string]interface{}); ok {
			current = next
		} else {
			return 0
		}
	}
	return 0
}

func getStringSlice(m map[string]interface{}, keys ...string) string {
	current := m
	for i, key := range keys {
		if i == len(keys)-1 {
			if v, ok := current[key].([]interface{}); ok {
				parts := []string{}
				for _, item := range v {
					if s, ok := item.(string); ok {
						parts = append(parts, s)
					}
				}
				return strings.Join(parts, ", ")
			}
			return ""
		}
		if next, ok := current[key].(map[string]interface{}); ok {
			current = next
		} else {
			return ""
		}
	}
	return ""
}

func getComplianceInfo(alert map[string]interface{}) string {
	rule, ok := alert["rule"].(map[string]interface{})
	if !ok {
		return ""
	}
	parts := []string{}
	if _, ok := rule["pci_dss"].([]interface{}); ok {
		parts = append(parts, "PCI-DSS")
	}
	if _, ok := rule["hipaa"].([]interface{}); ok {
		parts = append(parts, "HIPAA")
	}
	if _, ok := rule["gdpr"].([]interface{}); ok {
		parts = append(parts, "GDPR")
	}
	if _, ok := rule["nist_800_53"].([]interface{}); ok {
		parts = append(parts, "NIST-800-53")
	}
	if _, ok := rule["tsc"].([]interface{}); ok {
		parts = append(parts, "TSC")
	}
	return strings.Join(parts, ", ")
}

func processAlerts() {
	since := getLastTimestamp()
	alerts, err := fetchAlerts(since)
	if err != nil {
		log.Printf("[Worker] Wazuh fetch hatası: %v", err)
		return
	}

	if len(alerts) == 0 {
		return
	}

	log.Printf("[Worker] %d yeni alert işleniyor...", len(alerts))

	db, err := getDB()
	if err != nil {
		log.Printf("[Worker] ClickHouse bağlantı hatası: %v", err)
		return
	}
	defer db.Close()

	inserted := 0
	iocCount := 0

	for _, alert := range alerts {
		srcIP       := getString(alert, "data", "srcip")
		domain      := getString(alert, "data", "hostname")
		md5         := getString(alert, "data", "md5_after")
		agent       := getString(alert, "agent", "name")
		agentIP     := getString(alert, "agent", "ip")
		ruleDesc    := getString(alert, "rule", "description")
		ruleID      := getUint32(alert, "rule", "id")
		severity    := getUint8(alert, "rule", "level")
		firedTimes  := getUint32(alert, "rule", "firedtimes")
		fullLog     := getString(alert, "full_log")
		location    := getString(alert, "location")
		decoderName := getString(alert, "decoder", "name")
		eventID     := getString(alert, "id")
		ruleGroups  := getStringSlice(alert, "rule", "groups")
		compliance  := getComplianceInfo(alert)

		var ioc IOCResult
		for _, candidate := range []string{srcIP, domain, md5} {
			if candidate == "" {
				continue
			}
			result := checkIOC(candidate)
			if result.Matched == 1 {
				ioc = result
				iocCount++
				log.Printf("[Worker] IOC bulundu: %s (%s) score:%d desc:%s",
					candidate, result.EntityType, result.Score, result.Description)
				break
			}
		}

		iocValue := ""
		if ioc.Matched == 1 {
			for _, c := range []string{srcIP, domain, md5} {
				if c != "" {
					iocValue = c
					break
				}
			}
		}

		err = db.Exec(context.Background(),
			`INSERT INTO security.wazuh_events
			(agent_name, agent_ip, rule_id, rule_desc, severity, fired_times,
			 src_ip, domain, md5, full_log, location, decoder, rule_groups, compliance, event_id,
			 ioc_matched, ioc_type, ioc_value, ioc_description,
			 opencti_score, threat_actor, mitre_technique, tlp_level, cve)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			agent, agentIP, ruleID, ruleDesc, severity, firedTimes,
			srcIP, domain, md5, fullLog, location, decoderName, ruleGroups, compliance, eventID,
			ioc.Matched, ioc.EntityType, iocValue, ioc.Description,
			ioc.Score, ioc.ThreatActor, ioc.MitreTech, ioc.TLPLevel, ioc.CVE,
		)
		if err != nil {
			log.Printf("[Worker] Insert hatası: %v", err)
			continue
		}
		inserted++
	}

	log.Printf("[Worker] %d kayıt yazıldı | %d IOC eşleşmesi", inserted, iocCount)
}

func StartWorker() {
	log.Println("[Worker] Başlatıldı, 30 saniyede bir çalışacak")
	go func() {
		processAlerts()
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			processAlerts()
		}
	}()
}
