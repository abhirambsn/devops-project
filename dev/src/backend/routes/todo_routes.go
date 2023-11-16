package routes

import (
	"abhiram/devops-project-backend/controllers"

	"github.com/gofiber/fiber/v2"
)

func TodoRoutes(app* fiber.App, authMiddleware fiber.Handler) {
	app.Post("/todo", authMiddleware, controllers.AddTodo)
	app.Get("/todo/:todoId", authMiddleware, controllers.GetTodo)
	app.Put("/todo/:todoId", authMiddleware, controllers.EditTodo)
	app.Delete("/todo/:todoId", authMiddleware, controllers.DeleteTodo)
	app.Get("/todos", authMiddleware, controllers.GetTodosByUser)
}