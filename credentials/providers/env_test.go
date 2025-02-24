package providers

import (
	"github.com/aliyun/credentials-go/configure"
	"os"
	"testing"

	"github.com/aliyun/credentials-go/credentials/internal/utils"
	"github.com/stretchr/testify/assert"
)

func TestEnvironmentVariableCredentialsProvider(t *testing.T) {
	var envPrefix = configure.EnvPrefix
	rollback := utils.Memory(envPrefix+"ACCESS_KEY_ID", envPrefix+"ACCESS_KEY_SECRET", envPrefix+"SECURITY_TOKEN")
	defer rollback()

	p, err := NewEnvironmentVariableCredentialsProviderBuilder().Build()
	assert.Nil(t, err)
	_, err = p.GetCredentials()
	assert.EqualError(t, err, "unable to get credentials from enviroment variables, Access key ID must be specified via environment variable ("+envPrefix+"ACCESS_KEY_ID)")
	os.Setenv(envPrefix+"ACCESS_KEY_ID", "akid")
	_, err = p.GetCredentials()
	assert.EqualError(t, err, "unable to get credentials from enviroment variables, Access key secret must be specified via environment variable ("+envPrefix+"ACCESS_KEY_SECRET)")

	os.Setenv(envPrefix+"ACCESS_KEY_SECRET", "aksecret")
	cc, err := p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "aksecret", cc.AccessKeySecret)
	assert.Equal(t, "", cc.SecurityToken)
	assert.Equal(t, "env", cc.ProviderName)

	os.Setenv(envPrefix+"SECURITY_TOKEN", "token")
	cc, err = p.GetCredentials()
	assert.Nil(t, err)
	assert.Equal(t, "akid", cc.AccessKeyId)
	assert.Equal(t, "aksecret", cc.AccessKeySecret)
	assert.Equal(t, "token", cc.SecurityToken)
	assert.Equal(t, "env", cc.ProviderName)
}
