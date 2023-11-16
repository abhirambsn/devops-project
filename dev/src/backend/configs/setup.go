package configs

import (
	"context"
	"log"
	"time"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func ConnectDB() *mongo.Client {
	ctx, cancelCtx := context.WithTimeout(context.Background(), 10*time.Second)
	client, err :=mongo.Connect(ctx, options.Client().ApplyURI(EnvMongoURI()))
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer cancelCtx()
	return client
}

var DB *mongo.Client = ConnectDB()

// Helper Function to get Collection
func GetCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	collection := client.Database("devops-backend").Collection(collectionName)
	return collection
}