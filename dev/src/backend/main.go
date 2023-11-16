package main

import (
	"abhiram/devops-project-backend/configs"
	"abhiram/devops-project-backend/middlewares"
	"abhiram/devops-project-backend/routes"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"fmt"
)


func main() {
	app := fiber.New()
	
	app.Use(cors.New())
	
	configs.ConnectDB()
	jwt := middlewares.NewAuthMiddleware(configs.JWTSecret())

	routes.UserRoute(app, jwt)
	routes.TodoRoutes(app, jwt)
	routes.MiscRoutes(app)

	var addr = fmt.Sprintf(":%s", configs.Port())
	app.Listen(addr)
}