package main

import (
	"fmt"
	"log"
	"os"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type User struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	Email    string `gorm:"uniqueIndex;size:100" json:"email"`
	Password string `json:"-"`
	Name     string `json:"name"`
	Role     string `json:"role"`
}

var db *gorm.DB

func InitDB() {
	var err error

	// Có thể đọc config từ biến môi trường
	dbUser := getEnv("DB_USER", "root")
	dbPass := getEnv("DB_PASS", "123456") // đổi theo máy bạn
	dbHost := getEnv("DB_HOST", "127.0.0.1")
	dbPort := getEnv("DB_PORT", "3306")
	dbName := getEnv("DB_NAME", "authdb")

	// DSN dạng: user:pass@tcp(host:port)/dbname?params...
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		dbUser, dbPass, dbHost, dbPort, dbName,
	)

	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Không kết nối được MySQL: %v", err)
	}

	if err := db.AutoMigrate(&User{}); err != nil {
		log.Fatalf("AutoMigrate lỗi: %v", err)
	}
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
