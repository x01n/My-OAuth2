package oauth2

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

/*
 * CallbackRequest OAuth2 授权回调参数
 * 功能：承载授权服务器回跳到接入应用时的 code/state 或 error 参数
 */
type CallbackRequest struct {
	Code             string
	State            string
	Error            string
	ErrorDescription string
}

/*
 * CallbackResult OAuth2 授权回调处理结果
 * 功能：返回换取到的 Token，以及可选的 OIDC UserInfo
 */
type CallbackResult struct {
	Token    *Token
	UserInfo *UserInfo
}

/*
 * CallbackRequestFromValues 从 URL query/form values 构造回调请求
 */
func CallbackRequestFromValues(values url.Values) *CallbackRequest {
	return &CallbackRequest{
		Code:             values.Get("code"),
		State:            values.Get("state"),
		Error:            values.Get("error"),
		ErrorDescription: values.Get("error_description"),
	}
}

/*
 * CallbackRequestFromHTTPRequest 从 HTTP 请求 URL query 构造回调请求
 */
func CallbackRequestFromHTTPRequest(r *http.Request) *CallbackRequest {
	if r == nil {
		return &CallbackRequest{}
	}
	return CallbackRequestFromValues(r.URL.Query())
}

/*
 * HandleCallback 处理 OAuth2/OIDC 授权码回调
 * 功能：校验回调参数、交换 Token，并在配置了 UserInfoURL 时获取统一用户身份
 */
func (c *Client) HandleCallback(ctx context.Context, req *CallbackRequest) (*CallbackResult, error) {
	if req == nil {
		return nil, errors.New("oauth2: callback request is required")
	}
	if req.Error != "" {
		return nil, &OAuthError{
			Code:        req.Error,
			Description: req.ErrorDescription,
		}
	}
	if req.Code == "" {
		return nil, errors.New("oauth2: callback code is required")
	}
	if req.State == "" {
		return nil, errors.New("oauth2: callback state is required")
	}

	token, err := c.Exchange(ctx, req.Code, req.State)
	if err != nil {
		return nil, err
	}

	result := &CallbackResult{Token: token}
	if c.config.UserInfoURL != "" {
		userInfo, err := c.getUserInfoWithAccessToken(ctx, token.AccessToken)
		if err != nil {
			return nil, err
		}
		result.UserInfo = userInfo
	}
	return result, nil
}
