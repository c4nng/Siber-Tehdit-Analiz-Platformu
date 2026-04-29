package main

import (
	"log"
	"dashboard/handlers"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/websocket/v2"
)

func main() {
	handlers.StartWorker()

	app := fiber.New()

	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept",
	}))

	app.Get("/api/alerts",         handlers.GetAlerts)
	app.Get("/api/alerts/stats",   handlers.GetAlertStats)
	app.Get("/api/metrics",        handlers.GetMetrics)
	app.Get("/api/ai/health",      handlers.GetAIHealth)
	app.Post("/api/analyze",       handlers.AnalyzeAlert)
	app.Post("/api/analysis/save", handlers.SaveAnalysis)
	app.Get("/ws",                 websocket.New(handlers.WebSocketHandler))

	log.Println("[*] Dashboard backend başlatılıyor :8090")
	log.Fatal(app.Listen(":8090"))
}
