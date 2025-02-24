package providers

import (
	"github.com/aliyun/credentials-go/configure"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStaticSTSCredentialsProvider(t *testing.T) {
	_, err := NewStaticSTSCredentialsProviderBuilder().
		Build()
	assert.EqualError(t, err, "the access key id is empty")

	_, err = NewStaticSTSCredentialsProviderBuilder().
		WithAccessKeyId("akid").
		Build()
	assert.EqualError(t, err, "the access key secret is empty")

	_, err = NewStaticSTSCredentialsProviderBuilder().
		WithAccessKeyId("akid").
		WithAccessKeySecret("aksecret").
		Build()
	assert.EqualError(t, err, "the security token is empty")

	provider, err := NewStaticSTSCredentialsProviderBuilder().
		WithAccessKeyId("accessKeyId").
		WithAccessKeySecret("accessKeySecret").
		WithSecurityToken("securityToken").
		Build()
	assert.Nil(t, err)
	assert.Equal(t, "static_sts", provider.GetProviderName())

	cred, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "accessKeyId", cred.AccessKeyId)
	assert.Equal(t, "accessKeySecret", cred.AccessKeySecret)
	assert.Equal(t, "securityToken", cred.SecurityToken)
	assert.Equal(t, "static_sts", cred.ProviderName)
}

func TestStaticSTSCredentialsProviderWithEnv(t *testing.T) {
	originAKID := os.Getenv(configure.EnvPrefix + "ACCESS_KEY_ID")
	originAKSecret := os.Getenv(configure.EnvPrefix + "ACCESS_KEY_SECRET")
	originToken := os.Getenv(configure.EnvPrefix + "SECURITY_TOKEN")
	defer func() {
		os.Setenv(configure.EnvPrefix+"ACCESS_KEY_ID", originAKID)
		os.Setenv(configure.EnvPrefix+"ACCESS_KEY_SECRET", originAKSecret)
		os.Setenv(configure.EnvPrefix+"SECURITY_TOKEN", originToken)
	}()

	os.Setenv(configure.EnvPrefix+"ACCESS_KEY_ID", "akid_from_env")
	os.Setenv(configure.EnvPrefix+"ACCESS_KEY_SECRET", "aksecret_from_env")
	os.Setenv(configure.EnvPrefix+"SECURITY_TOKEN", "token_from_env")
	provider, err := NewStaticSTSCredentialsProviderBuilder().
		Build()
	assert.Nil(t, err)
	assert.Equal(t, "static_sts", provider.GetProviderName())

	cred, err := provider.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid_from_env", cred.AccessKeyId)
	assert.Equal(t, "aksecret_from_env", cred.AccessKeySecret)
	assert.Equal(t, "token_from_env", cred.SecurityToken)
	assert.Equal(t, "static_sts", cred.ProviderName)
}
