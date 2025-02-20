package credentials

import (
	"errors"
	"github.com/aliyun/credentials-go/configure"
	"os"

	"github.com/alibabacloud-go/tea/tea"
)

type envProvider struct{}

var providerEnv = new(envProvider)

const (
	EnvVarAccessKeyId     = configure.EnvPrefix + "ACCESS_KEY_Id"
	EnvVarAccessKeyIdNew  = configure.EnvPrefix + "ACCESS_KEY_ID"
	EnvVarAccessKeySecret = configure.EnvPrefix + "ACCESS_KEY_SECRET"
)

func newEnvProvider() Provider {
	return &envProvider{}
}

func (p *envProvider) resolve() (config *Config, err error) {
	accessKeyId, ok1 := os.LookupEnv(EnvVarAccessKeyIdNew)
	if !ok1 || accessKeyId == "" {
		accessKeyId, ok1 = os.LookupEnv(EnvVarAccessKeyId)
	}
	accessKeySecret, ok2 := os.LookupEnv(EnvVarAccessKeySecret)
	if !ok1 || !ok2 {
		return nil, nil
	}
	if accessKeyId == "" {
		return nil, errors.New(EnvVarAccessKeyIdNew + " or " + EnvVarAccessKeyId + " cannot be empty")
	}
	if accessKeySecret == "" {
		return nil, errors.New(EnvVarAccessKeySecret + " cannot be empty")
	}

	securityToken := os.Getenv(configure.EnvPrefix + "SECURITY_TOKEN")

	if securityToken != "" {
		config = &Config{
			Type:            tea.String("sts"),
			AccessKeyId:     tea.String(accessKeyId),
			AccessKeySecret: tea.String(accessKeySecret),
			SecurityToken:   tea.String(securityToken),
		}
		return
	}

	config = &Config{
		Type:            tea.String("access_key"),
		AccessKeyId:     tea.String(accessKeyId),
		AccessKeySecret: tea.String(accessKeySecret),
	}

	return
}
