package configs

import (
	"log"
	"os"
	"github.com/joho/godotenv"
)

func EnvMongoURI() string {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error Loading .env File")
	}
	return os.Getenv("MONGODB_URI")
}

func JWTSecret() string {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error Loading .env File")
	}
	return os.Getenv("JWT_SECRET")
}

func Port() string {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error Loading .env File")
	}

	return os.Getenv("PORT")
}