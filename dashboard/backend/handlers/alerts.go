package handlers

import (
	"context"
	"fmt"
	"time"
	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/gofiber/fiber/v2"
)

func getDB() (clickhouse.Conn, error) {
	return clickhouse.Open(&clickhouse.Options{
		Addr: []string{"localhost:9001"},
		Auth: clickhouse.Auth{
			Database: "security",
			Username: "default",
			Password: "clickhouse123",
		},
	})
}

type Alert struct {
	Ts             string `json:"ts"`
	AgentName      string `json:"agent_name"`
	AgentIP        string `json:"agent_ip"`
	RuleID         uint32 `json:"rule_id"`
	RuleDesc       string `json:"rule_desc"`
	Severity       uint8  `json:"severity"`
	FiredTimes     uint32 `json:"fired_times"`
	SrcIP          string `json:"src_ip"`
	Domain         string `json:"domain"`
	Md5            string `json:"md5"`
	FullLog        string `json:"full_log"`
	Location       string `json:"location"`
	Decoder        string `json:"decoder"`
	RuleGroups     string `json:"rule_groups"`
	Compliance     string `json:"compliance"`
	EventID        string `json:"event_id"`
	IocMatched     uint8  `json:"ioc_matched"`
	IocType        string `json:"ioc_type"`
	IocValue       string `json:"ioc_value"`
	IocDescription string `json:"ioc_description"`
	OpenctiScore   uint8  `json:"opencti_score"`
	ThreatActor    string `json:"threat_actor"`
	MitreTechnique string `json:"mitre_technique"`
	TLPLevel       string `json:"tlp_level"`
	CVE            string `json:"cve"`
	AIAnalysis     string `json:"ai_analysis"`
	AIAnalyzedAt   string `json:"ai_analyzed_at"`
}

func GetAlerts(c *fiber.Ctx) error {
	limit   := c.QueryInt("limit", 50)
	agent   := c.Query("agent", "")
	iocOnly := c.QueryBool("ioc_only", false)

	db, err := getDB()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer db.Close()

	query := fmt.Sprintf(`
		SELECT ts, agent_name, agent_ip, rule_id, rule_desc, severity, fired_times,
		       src_ip, domain, md5, full_log, location, decoder, rule_groups, compliance, event_id,
		       ioc_matched, ioc_type, ioc_value, ioc_description,
		       opencti_score, threat_actor, mitre_technique, tlp_level, cve,
		       ai_analysis, ai_analyzed_at
		FROM security.wazuh_events
		WHERE 1=1 %s %s
		ORDER BY ts DESC
		LIMIT %d`,
		func() string {
			if agent != "" {
				return fmt.Sprintf("AND agent_name = '%s'", agent)
			}
			return ""
		}(),
		func() string {
			if iocOnly {
				return "AND ioc_matched = 1"
			}
			return ""
		}(),
		limit,
	)

	rows, err := db.Query(context.Background(), query)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer rows.Close()

	alerts := []Alert{}
	for rows.Next() {
		var a Alert
		var ts, aiAt time.Time
		if err := rows.Scan(
			&ts, &a.AgentName, &a.AgentIP, &a.RuleID, &a.RuleDesc, &a.Severity, &a.FiredTimes,
			&a.SrcIP, &a.Domain, &a.Md5, &a.FullLog, &a.Location, &a.Decoder,
			&a.RuleGroups, &a.Compliance, &a.EventID,
			&a.IocMatched, &a.IocType, &a.IocValue, &a.IocDescription,
			&a.OpenctiScore, &a.ThreatActor, &a.MitreTechnique, &a.TLPLevel, &a.CVE,
			&a.AIAnalysis, &aiAt,
		); err != nil {
			fmt.Println("Scan hatası:", err)
			continue
		}
		a.Ts = ts.In(time.FixedZone("UTC+3", 3*60*60)).Format("2006-01-02 15:04:05")
		if aiAt.Year() > 1970 {
			a.AIAnalyzedAt = aiAt.In(time.FixedZone("UTC+3", 3*60*60)).Format("2006-01-02 15:04:05")
		}
		alerts = append(alerts, a)
	}
	return c.JSON(alerts)
}

func GetAlertStats(c *fiber.Ctx) error {
	db, err := getDB()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer db.Close()

	stats := fiber.Map{}

	row := db.QueryRow(context.Background(), "SELECT count() FROM security.wazuh_events")
	var total uint64; row.Scan(&total)
	stats["total"] = total

	row = db.QueryRow(context.Background(), "SELECT count() FROM security.wazuh_events WHERE ioc_matched = 1")
	var iocTotal uint64; row.Scan(&iocTotal)
	stats["ioc_matched"] = iocTotal

	row = db.QueryRow(context.Background(), "SELECT count() FROM security.wazuh_events WHERE severity >= 10")
	var critical uint64; row.Scan(&critical)
	stats["critical"] = critical

	row = db.QueryRow(context.Background(), "SELECT count(DISTINCT agent_name) FROM security.wazuh_events")
	var agents uint64; row.Scan(&agents)
	stats["agents"] = agents

	row = db.QueryRow(context.Background(), "SELECT count() FROM security.wazuh_events WHERE ai_analysis != ''")
	var aiAnalyzed uint64; row.Scan(&aiAnalyzed)
	stats["ai_analyzed"] = aiAnalyzed

	return c.JSON(stats)
}

type SaveAnalysisRequest struct {
	RowTS    string `json:"ts"`
	Agent    string `json:"agent_name"`
	RuleID   uint32 `json:"rule_id"`
	Analysis string `json:"analysis"`
}

func SaveAnalysis(c *fiber.Ctx) error {
	var req SaveAnalysisRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": err.Error()})
	}

	db, err := getDB()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	defer db.Close()

	query := fmt.Sprintf(`
		ALTER TABLE security.wazuh_events UPDATE
		ai_analysis = '%s', ai_analyzed_at = now()
		WHERE ts = '%s' AND agent_name = '%s' AND rule_id = %d`,
		req.Analysis, req.RowTS, req.Agent, req.RuleID,
	)

	err = db.Exec(context.Background(), query)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"status": "ok"})
}
