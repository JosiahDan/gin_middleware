package main

import (
	"gin_middleware/jwtVerify/model"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.GET("/JWTverify", model.JWTVerify(), func(c *gin.Context) {
		//获取上下文中的claims
		req, _ := c.Get("claims")
		c.JSON(200, req)
	})
	r.GET("/getToken", func(c *gin.Context) {
		var claims model.Claims
		claims.ID = "admin"
		claims.Level = "A"
		claims.IsPass = true

		token := claims.SignToken()
		c.JSON(200, token)
	})
	//
	//r.GET("/parse", func(c *gin.Context) {
	//	var claims model.Claims
	//	tokenString := c.Query("token")
	//	claims.ParseToken(tokenString)
	//	c.JSON(200, claims)
	//
	//})

	r.Run()
}
