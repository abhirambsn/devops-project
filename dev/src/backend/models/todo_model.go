package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Todo struct {
	Id			primitive.ObjectID			`json:"_id,omitempty"`
	Title		string						`json:"title,omitempty" validate:"required"`
	Description	string						`json:"description,omitempty" validate:"required"`
	Completed	bool						`json:"completed,omitempty"`
	Author		primitive.ObjectID			`json:"author,omitempty"`
}