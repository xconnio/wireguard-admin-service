package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/xconnio/wireguard-admin-service"
)

type DeviceRequest struct {
	DeviceName string `json:"device_name" binding:"required"`
}

func main() {
	r := gin.Default()

	const imageDir = "./qr-codes"

	if err := os.MkdirAll(imageDir, os.ModePerm); err != nil {
		log.Fatal(err)
	}

	r.Static("qr", imageDir)

	r.POST("/device", func(c *gin.Context) {
		var req DeviceRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "device_name is required"})
			return
		}

		if err := wireguard_admin_service.AddUser(req.DeviceName); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		qrCode := fmt.Sprintf("http://%s/qr/%s-client-qr.png", c.Request.Host, req.DeviceName)

		c.JSON(http.StatusOK, gin.H{
			"qr_code": qrCode,
		})
	})

	log.Fatalln(r.Run("0.0.0.0:8000"))
}
