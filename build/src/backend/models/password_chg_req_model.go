package models

type PasswordChangeRequest struct {
	OldPassword			string		`json:"oldpassword" validate:"required"`
	NewPassword			string		`json:"newpassword" validate:"required"`
}