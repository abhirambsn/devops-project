package controllers

import (
	"abhiram/devops-project-backend/configs"
	"abhiram/devops-project-backend/models"
	"abhiram/devops-project-backend/responses"
	"context"
	"log"
	"net/http"
	"reflect"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var todoCollection = configs.GetCollection(configs.DB, "todos")
var todoValidator = validator.New()

// POST /todo
func AddTodo(c *fiber.Ctx) error {
	ctx, cancelCtx := context.WithTimeout(context.Background(), 10*time.Second)
	var todoData models.Todo
	defer cancelCtx()

	if err := c.BodyParser(&todoData); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	if validationErr := todoValidator.Struct(&todoData); validationErr != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: &fiber.Map{"error": validationErr.Error()}})
	}

	authorData := GetUserDetailsFromToken(c)
	authorId, convErr := primitive.ObjectIDFromHex(authorData[0])

	if convErr != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": convErr.Error()}})
	}

	newTodo := models.Todo{
		Id:          primitive.NewObjectID(),
		Title:       todoData.Title,
		Description: todoData.Description,
		Completed:   false,
		Author:      authorId,
	}

	result, err := todoCollection.InsertOne(ctx, newTodo)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	return c.Status(http.StatusCreated).JSON(responses.UserResponse{Status: http.StatusCreated, Message: "success", Data: &fiber.Map{"todo": result}})
}

// GET /todo/todoID
func GetTodo(c *fiber.Ctx) error {
	ctx, cancelCtx := context.WithTimeout(context.Background(), 10*time.Second)
	var todo models.Todo
	defer cancelCtx()

	todoId := c.Params("todoId")
	objId, err := primitive.ObjectIDFromHex(todoId)

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	err = todoCollection.FindOne(ctx, bson.M{"id": objId}).Decode(&todo)
	
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}
	return c.Status(http.StatusOK).JSON(responses.UserResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"todo": todo}})
}

// Helper Function to update Objects
func UpdateTodo(todo *models.Todo, update map[string]interface{}) {
	value := reflect.ValueOf(todo).Elem()

	for key,newVal := range update {
		field := value.FieldByName(key)
		if field.IsValid() && field.CanSet() {
			if !reflect.DeepEqual(field.Interface(), newVal) {
				field.Set(reflect.ValueOf(newVal))
			}
		}
	}
}


func isEmpty(field reflect.Value) bool {
	zeroValue := reflect.Zero(field.Type()).Interface()
	return reflect.DeepEqual(field.Interface(), zeroValue)
}

func ConvertBodyToMap(todo models.Todo) map[string]interface{} {
	result := make(map[string]interface{})

	value := reflect.ValueOf(todo)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}

	if value.Kind() == reflect.Struct {
		typeOfObj := value.Type()

		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			fieldName := typeOfObj.Field(i).Name
			if typeOfObj.Field(i).PkgPath == "" && !isEmpty(field) {
				result[fieldName] = field.Interface()
			}
		}
	}

	return result
}

// PUT /todo/todoID
func EditTodo(c *fiber.Ctx) error {
	ctx, cancelCtx := context.WithTimeout(context.Background(), 10*time.Second)
	var existingTodo models.Todo
	var newTodo models.Todo
	defer cancelCtx()

	if err := c.BodyParser(&newTodo); err != nil {
		log.Fatal(err)
	}

	todoId := c.Params("todoId")
	objId, err := primitive.ObjectIDFromHex(todoId)

	if err != nil {
		log.Fatal(err)
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})

	}

	err = todoCollection.FindOne(ctx, bson.M{"id": objId}).Decode(&existingTodo)
	if err != nil {
		log.Fatal(err)
		return c.Status(http.StatusNotFound).JSON(responses.UserResponse{Status: http.StatusNotFound, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	UpdateTodo(&existingTodo, ConvertBodyToMap(newTodo))
	result, err := todoCollection.UpdateOne(ctx, bson.M{"id": objId}, bson.M{"$set": existingTodo})
	
	if err != nil {
		log.Fatal(err)
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	return c.Status(http.StatusOK).JSON(responses.UserResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"result": result}})
}

// DELETE /todo/todoID
func DeleteTodo(c *fiber.Ctx) error {
	ctx, cancelCtx := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCtx()

	todoId := c.Params("todoId")
	author := GetUserDetailsFromToken(c)
	authorId := author[0]

	authorObjId, aOid_err := primitive.ObjectIDFromHex(authorId)
	todoObjId, tOid_err := primitive.ObjectIDFromHex(todoId)

	if aOid_err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": aOid_err.Error()}})
	}

	if tOid_err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": tOid_err.Error()}})
	}

	deleteRes, err := todoCollection.DeleteOne(ctx, bson.M{"id": todoObjId, "author": authorObjId})

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	return c.Status(http.StatusOK).JSON(responses.UserResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"result": deleteRes}})
}

// GET /todos
func GetTodosByUser(c *fiber.Ctx) error {
	ctx, cancelCtx := context.WithTimeout(context.Background(), 10*time.Second)
	var todos []models.Todo
	defer cancelCtx()

	author := GetUserDetailsFromToken(c)
	authorId := author[0]

	objId, err := primitive.ObjectIDFromHex(authorId)

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	cursor, err := todoCollection.Find(ctx, bson.M{"author": objId})
	
	if err != nil {
		log.Fatal(err)
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	for cursor.Next(ctx) {
		var todo models.Todo
		if err := cursor.Decode(&todo); err != nil {
			log.Fatal(err)
			return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})
		}
		todos = append(todos, todo)
	}

	if err := cursor.Err(); err != nil {
		log.Fatal(err)
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	return c.Status(http.StatusOK).JSON(responses.UserResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"todos": todos}})
}