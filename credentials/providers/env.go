package providers

import (
	"fmt"
	"github.com/aliyun/credentials-go/configure"
	"os"
)

type EnvironmentVariableCredentialsProvider struct {
}

type EnvironmentVariableCredentialsProviderBuilder struct {
	provider *EnvironmentVariableCredentialsProvider
}

func NewEnvironmentVariableCredentialsProviderBuilder() *EnvironmentVariableCredentialsProviderBuilder {
	return &EnvironmentVariableCredentialsProviderBuilder{
		provider: &EnvironmentVariableCredentialsProvider{},
	}
}

func (builder *EnvironmentVariableCredentialsProviderBuilder) Build() (provider *EnvironmentVariableCredentialsProvider, err error) {
	provider = builder.provider
	return
}

func (provider *EnvironmentVariableCredentialsProvider) GetCredentials() (cc *Credentials, err error) {
	accessKeyId := os.Getenv(configure.EnvPrefix + "ACCESS_KEY_ID")

	if accessKeyId == "" {
		err = fmt.Errorf("unable to get credentials from enviroment variables, Access key ID must be specified via environment variable (" + configure.EnvPrefix + "ACCESS_KEY_ID)")
		return
	}

	accessKeySecret := os.Getenv(configure.EnvPrefix + "ACCESS_KEY_SECRET")

	if accessKeySecret == "" {
		err = fmt.Errorf("unable to get credentials from enviroment variables, Access key secret must be specified via environment variable (" + configure.EnvPrefix + "ACCESS_KEY_SECRET)")
		return
	}

	securityToken := os.Getenv(configure.EnvPrefix + "SECURITY_TOKEN")

	cc = &Credentials{
		AccessKeyId:     accessKeyId,
		AccessKeySecret: accessKeySecret,
		SecurityToken:   securityToken,
		ProviderName:    provider.GetProviderName(),
	}

	return
}

func (provider *EnvironmentVariableCredentialsProvider) GetProviderName() string {
	return "env"
}
