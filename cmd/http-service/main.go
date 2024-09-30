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

	const qrDir = "./qr-codes"
	if err := os.MkdirAll(qrDir, os.ModePerm); err != nil {
		log.Fatal(err)
	}
	r.Static("qrs", qrDir)

	const cfgDir = "./configs"
	if err := os.MkdirAll(cfgDir, os.ModePerm); err != nil {
		log.Fatal(err)
	}
	r.Static("configs", cfgDir)

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

		qrCode := fmt.Sprintf("http://%s/qrs/%s-client-qr.png", c.Request.Host, req.DeviceName)
		config := fmt.Sprintf("http://%s/configs/client-%s.conf", c.Request.Host, req.DeviceName)

		c.JSON(http.StatusOK, gin.H{
			"qr_code": qrCode,
			"config":  config,
		})
	})

	log.Fatalln(r.Run("0.0.0.0:8000"))
}
