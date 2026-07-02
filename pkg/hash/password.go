package hash

import "golang.org/x/crypto/bcrypt"

// HashPassword generates a bcrypt hash for the given password.
func HashPassword(password string) (string, error) {
    // 12 is the bcrypt cost. Higher is more secure but slower.
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
    return string(bytes), err
}

// CheckPasswordHash compares a plain-text password with a stored hash.
func CheckPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}