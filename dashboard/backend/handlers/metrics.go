package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

func GetMetrics(c *fiber.Ctx) error {
	cpuPercent, _ := cpu.Percent(0, false)
	memInfo, _ := mem.VirtualMemory()
	diskInfo, _ := disk.Usage("/")
	netInfo, _ := net.IOCounters(false)

	metrics := fiber.Map{
		"cpu": fiber.Map{
			"percent": cpuPercent[0],
		},
		"memory": fiber.Map{
			"total":       memInfo.Total,
			"used":        memInfo.Used,
			"percent":     memInfo.UsedPercent,
		},
		"disk": fiber.Map{
			"total":       diskInfo.Total,
			"used":        diskInfo.Used,
			"percent":     diskInfo.UsedPercent,
		},
		"network": fiber.Map{
			"bytes_sent": netInfo[0].BytesSent,
			"bytes_recv": netInfo[0].BytesRecv,
		},
	}
	return c.JSON(metrics)
}
