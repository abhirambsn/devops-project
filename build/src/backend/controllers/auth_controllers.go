package controllers

import (
	"abhiram/devops-project-backend/configs"
	"abhiram/devops-project-backend/models"
	"abhiram/devops-project-backend/responses"
	"context"
	"log"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	jtoken "github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/andskur/argon2-hashing"
	// "go.mongodb.org/mongo-driver/mongo"
)

var userCollection = configs.GetCollection(configs.DB, "users")
var authValidator = validator.New()

func CreateUser(c *fiber.Ctx) error {
	ctx, cancelCtx := context.WithTimeout(context.Background(), 10*time.Second)
	var user models.User
	defer cancelCtx()

	if err := c.BodyParser(&user); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	if validationErr := authValidator.Struct(&user); validationErr != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: &fiber.Map{"error": validationErr.Error()}})
	}

	// Hash the Password
	pwdHash, err := argon2.GenerateFromPassword([]byte(user.Password), argon2.DefaultParams)

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	newUser := models.User{
		Id:       primitive.NewObjectID(),
		Username: user.Username,
		Password: string(pwdHash),
		FullName: user.FullName,
	}

	result, err := userCollection.InsertOne(ctx, newUser)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	return c.Status(http.StatusCreated).JSON(responses.UserResponse{Status: http.StatusCreated, Message: "success", Data: &fiber.Map{"user": result}})
}

func GetUser(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	userId := c.Params("userId")
	var user models.User
	defer cancel()

	objId, _ := primitive.ObjectIDFromHex(userId)

	err := userCollection.FindOne(ctx, bson.M{"_id": objId}, options.FindOne().SetProjection(bson.M{"password": 0})).Decode(&user)

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	return c.Status(http.StatusOK).JSON(responses.UserResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"user": user}})
}

func EditPassword(c *fiber.Ctx) error {
	ctx, cancelCtx := context.WithTimeout(context.Background(), 10*time.Second)
	var passwordChgReq models.PasswordChangeRequest
	var existingUser models.User
	defer cancelCtx()

	if err := c.BodyParser(&passwordChgReq); err != nil {
		log.Fatal(err)
	}

	// Check Old Password with user
	user := GetUserDetailsFromToken(c)
	userId := user[0]
	objId, err := primitive.ObjectIDFromHex(userId)

	if err != nil {
		log.Fatal(err)
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	err = userCollection.FindOne(ctx, bson.M{"id": objId}).Decode(&existingUser)

	if err != nil {
		log.Fatal(err)
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	err = argon2.CompareHashAndPassword([]byte(existingUser.Password), []byte(passwordChgReq.OldPassword))

	if err != nil {
		log.Fatal(err)
		return c.Status(http.StatusForbidden).JSON(responses.UserResponse{Status: http.StatusForbidden, Message: "error", Data: &fiber.Map{"error": "Incorrect Old Password"}})
	}

	newPassword, hashErr := argon2.GenerateFromPassword([]byte(passwordChgReq.NewPassword), argon2.DefaultParams)

	if hashErr != nil {
		log.Fatal(hashErr)
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	update := bson.M{"password": string(newPassword)}

	result, err := userCollection.UpdateOne(ctx, bson.M{"id": objId}, bson.M{"$set": update})

	if err != nil {
		log.Fatal(err)
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	return c.Status(http.StatusOK).JSON(responses.UserResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"result": result}})
}

func LoginUser(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var userData models.LoginRequest
	var queryUser models.User
	defer cancel()

	if err := c.BodyParser(&userData); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	if validationErr := authValidator.Struct(&userData); validationErr != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: &fiber.Map{"error": validationErr.Error()}})
	}

	// Get User
	err := userCollection.FindOne(ctx, bson.M{"username": userData.Username}).Decode(&queryUser)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	// Comapare Hash
	hashCompareError := argon2.CompareHashAndPassword([]byte(queryUser.Password), []byte(userData.Password))
	if hashCompareError != nil {
		return c.Status(http.StatusUnauthorized).JSON(responses.UserResponse{Status: http.StatusUnauthorized, Message: "unauthorized", Data: &fiber.Map{"error": "Wrong Password"}})
	}

	day := time.Hour * 24
	claims := jtoken.MapClaims{
		"ID":       queryUser.Id,
		"Username": queryUser.Username,
		"FullName": queryUser.FullName,
		"exp":      time.Now().Add(day * 1).Unix(),
	}

	// Generate JWT
	tokenGenerator := jtoken.NewWithClaims(jtoken.SigningMethodHS256, claims)
	token, err := tokenGenerator.SignedString([]byte(configs.JWTSecret()))

	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: &fiber.Map{"error": err.Error()}})
	}

	return c.Status(http.StatusOK).JSON(responses.UserResponse{Status: http.StatusOK, Message: "authenticated", Data: &fiber.Map{"token": token}})
}

func GetUserDetailsFromToken(c *fiber.Ctx) []string {
	user := c.Locals("user").(*jtoken.Token)
	claims := user.Claims.(jtoken.MapClaims)
	userId := claims["ID"].(string)
	username := claims["Username"].(string)
	fullname := claims["FullName"].(string)
	return []string{userId, username, fullname}
}

func GetProfile(c *fiber.Ctx) error {
	userData := GetUserDetailsFromToken(c)
	return c.Status(http.StatusOK).JSON(responses.UserResponse{Status: http.StatusOK, Message: "success", Data: &fiber.Map{"user": &fiber.Map{"id": userData[0], "username": userData[1], "fullname": userData[2]}}})
}
