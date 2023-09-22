package middleware

import (
	"encoding/json"
	"os"

	"gitlab.beeps.cn/common/cl"
	"gitlab.beeps.cn/common/logs"
	"gitlab.beeps.cn/common/render"

	"github.com/gin-gonic/gin"
)

type RoleType int

const (
	Normal   RoleType = 10000 //普通用户
	Vip      RoleType = 10010 //vip用户
	Admin    RoleType = 10020 //管理员		-	官方标识[X] 管理权限[O]
	Official RoleType = 10030 //官方用户	-	官方标识[O] 管理权限[O] 平台管理权限[O]
	Root     RoleType = 10100 //超级管理员	-	官方标识[O] 管理权限[O]	平台管理权限[O]
)

type (
	AuthModel struct {
		UserId           string   //平台用户id
		UserRole         RoleType //用户角色
		Mid              string   //机器码
		Os               string   //操作系统；android、ios、web
		Ip               string   //客户端ip
		Amr              string   //授权方式；phone.手机登录；pwd.密码登录；token.令牌登录；account.第三方登录
		AuthTime         int64    //授权时间戳
		TokenExpire      int64    //过期时间戳
		TokenForceExpire int64    //强制过期时间戳；过期后也不可用于login
	}
)

var (
	checkTokenApi = os.Getenv("AUTH_CHECK_TOKEN_API")
)

func MiddlewareAuthHandler(c *gin.Context) {
	var req struct {
		Token string `json:"token"`
	}
	var resp cl.ClRespModel
	var tokenInfo AuthModel

	token := c.GetHeader("Authorization")
	req.Token = token
	err := cl.PostJsonStruct(checkTokenApi, &req, &resp)
	if err != nil {
		render.Err(c, render.Unauthorized)
		c.Abort()
		return
	}
	if resp.Code != 1 {
		render.ErrCustom(c, render.Unauthorized.Code(), resp.Msg)
		c.Abort()
		return
	}
	info, ok := resp.Data.(map[string]interface{})
	if !ok {
		render.Err(c, render.Unauthorized)
		c.Abort()
		return
	}

	infoX, err := json.Marshal(&info)
	if err != nil {
		logs.Std.Error(err)
		render.Err(c, render.Unauthorized)
		c.Abort()
		return
	}
	err = json.Unmarshal(infoX, &tokenInfo)
	if err != nil {
		render.Err(c, render.Unauthorized)
		c.Abort()
		return
	}
	c.Set("tokenInfo", tokenInfo)
	c.Next()
}

func UnmarshalToken(c *gin.Context) AuthModel {
	var tokenInfo AuthModel
	info, ok := c.Get("tokenInfo")
	if !ok {
		return tokenInfo
	}
	tokenInfo, _ = info.(AuthModel)
	return tokenInfo
}

func MiddlewareAuth() gin.HandlerFunc {
	return MiddlewareAuthHandler
}
