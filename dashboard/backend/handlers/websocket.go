package handlers

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gofiber/websocket/v2"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

func WebSocketHandler(c *websocket.Conn) {
	defer c.Close()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		db, err := getDB()
		if err != nil {
			continue
		}

		// Son 10 alert
		rows, err := db.Query(context.Background(),
			"SELECT ts, agent_name, rule_id, rule_desc, severity, src_ip, ioc_matched, ioc_type, ioc_value FROM security.wazuh_events ORDER BY ts DESC LIMIT 10")
		if err != nil {
			db.Close()
			continue
		}

		alerts := []Alert{}
		for rows.Next() {
			var a Alert
			rows.Scan(&a.Ts, &a.AgentName, &a.RuleID, &a.RuleDesc,
				&a.Severity, &a.SrcIP, &a.IocMatched, &a.IocType, &a.IocValue)
			alerts = append(alerts, a)
		}
		rows.Close()
		db.Close()

		// Metrikler
		cpuPercent, _ := cpu.Percent(0, false)
		memInfo, _ := mem.VirtualMemory()

		payload := map[string]interface{}{
			"alerts": alerts,
			"metrics": map[string]interface{}{
				"cpu_percent": cpuPercent[0],
				"mem_percent": memInfo.UsedPercent,
			},
		}

		data, _ := json.Marshal(payload)
		if err := c.WriteMessage(websocket.TextMessage, data); err != nil {
			break
		}
	}
}
