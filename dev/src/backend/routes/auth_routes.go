package routes

import (
	"abhiram/devops-project-backend/controllers"
	"github.com/gofiber/fiber/v2"
)

func UserRoute(app *fiber.App, authMiddleware fiber.Handler) {
	app.Post("/user", controllers.CreateUser)
	app.Post("/login", controllers.LoginUser)
	app.Get("/users/:userId", controllers.GetUser)
	app.Get("/user", authMiddleware, controllers.GetProfile)
	app.Put("/user", authMiddleware, controllers.EditPassword)
}