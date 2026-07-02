package domain

import(
	"time"
	"github.com/google/uuid"
)


type User struct {
    ID           uuid.UUID `json:"id"`
    Email        string    `json:"email"`
    Username     string    `json:"username"`
    PasswordHash string    `json:"-"` 
    DisplayName  string    `json:"display_name"`
    AvatarURL    *string   `json:"avatar_url,omitempty"` // Pointer = nullable
    IsActive     bool      `json:"is_active"`
    IsVerified   bool      `json:"is_verified"`
    CreatedAt    time.Time `json:"created_at"`
    UpdatedAt    time.Time `json:"updated_at"`
}


type UserCreate struct {
    Email       string `json:"email" validate:"required,email"`
    Username    string `json:"username" validate:"required,min=3,max=30,alphanum"`
    Password    string `json:"password" validate:"required,min=8,max=128"`
    DisplayName string `json:"display_name" validate:"required,min=1,max=50"`
}

type UserLogin struct {
    Email    string `json:"email" validate:"required,email"`
    Password string `json:"password" validate:"required"`
}

type UserResponse struct {
    ID          uuid.UUID `json:"id"`
    Email       string    `json:"email"`
    Username    string    `json:"username"`
    DisplayName string    `json:"display_name"`
    AvatarURL   *string   `json:"avatar_url,omitempty"`
    CreatedAt   time.Time `json:"created_at"`
}


func (u *User) ToResponse() *UserResponse {
    return &UserResponse{
        ID:          u.ID,
        Email:       u.Email,
        Username:    u.Username,
        DisplayName: u.DisplayName,
        AvatarURL:   u.AvatarURL,
        CreatedAt:   u.CreatedAt,
    }
}