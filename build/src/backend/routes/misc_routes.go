package routes

import (
	"abhiram/devops-project-backend/responses"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

func HealthCheck(c *fiber.Ctx) error {
	return c.Status(http.StatusOK).JSON(responses.UserResponse{Status: http.StatusOK, Message: "ok", Data: nil})
}

func MiscRoutes(app *fiber.App) {
	app.Get("/health", HealthCheck)
}