package model

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"time"
)

//claims接口
type ClaimsOpt interface {
	SignToken() string
}

//claims结构体
type Claims struct {
	ID     string `json:"id"`
	IsPass bool   `json:"isPass"`
	Level  string `json:"level"`
	jwt.StandardClaims
}

//签发token
func (c *Claims) SignToken() string {
	//生效时间(此处设置为签发前一分钟生效)
	c.NotBefore = time.Now().Unix() - 60
	c.ExpiresAt = time.Now().Unix() + 60*2
	c.Issuer = "server"

	//实例化token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	//token加密撒盐
	salt := []byte("server")
	ss, err := token.SignedString(salt)

	if err != nil {
		return ""
	}

	//返回加密后的token
	return ss
}

//解析token
func (c *Claims) ParseToken(token string) error {
	//解析出token
	tokenClaims, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("server"), nil
	})

	if err != nil {
		return err
	}

	//验证token是否有效
	if customClaims, ok := tokenClaims.Claims.(*Claims); ok && tokenClaims.Valid {
		c.ID = customClaims.ID
		c.Level = customClaims.Level
		c.IsPass = customClaims.IsPass

		return nil
	}

	return err
}

func JWTVerify() gin.HandlerFunc {
	return func(c *gin.Context) {
		var customClaims Claims
		token := c.Query("token")
		if token == "" {
			c.Set("claims", "无token需请求签名")
		}
		customClaims.ParseToken(token)
		//上下文中设置claims
		c.Set("claims", customClaims)
	}
}
