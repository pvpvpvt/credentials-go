package credentials

import (
	"fmt"
	"github.com/aliyun/credentials-go/configure"
	"os"
	"testing"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
)

func TestEnvresolve(t *testing.T) {
	p := newEnvProvider()
	assert.Equal(t, &envProvider{}, p)
	originAccessKeyIdNew := os.Getenv(EnvVarAccessKeyIdNew)
	originAccessKeyId := os.Getenv(EnvVarAccessKeyId)
	originAccessKeySecret := os.Getenv(EnvVarAccessKeySecret)
	originSecurityToken := os.Getenv(configure.EnvPrefix + "SECURITY_TOKEN")
	os.Setenv(EnvVarAccessKeyId, "")
	os.Setenv(EnvVarAccessKeyIdNew, "")
	os.Setenv(EnvVarAccessKeySecret, "")
	os.Setenv(configure.EnvPrefix+"SECURITY_TOKEN", "")
	defer func() {
		os.Setenv(EnvVarAccessKeyIdNew, originAccessKeyIdNew)
		os.Setenv(EnvVarAccessKeyId, originAccessKeyId)
		os.Setenv(EnvVarAccessKeySecret, originAccessKeySecret)
		os.Setenv(configure.EnvPrefix+"SECURITY_TOKEN", originSecurityToken)
	}()
	c, err := p.resolve()
	assert.Nil(t, c)
	assert.EqualError(t, err, fmt.Sprintf("%sACCESS_KEY_ID or %sACCESS_KEY_Id cannot be empty", configure.EnvPrefix, configure.EnvPrefix))

	os.Setenv(EnvVarAccessKeyIdNew, "")
	os.Setenv(EnvVarAccessKeyId, "")
	c, err = p.resolve()
	assert.Nil(t, c)
	assert.EqualError(t, err, fmt.Sprintf("%sACCESS_KEY_ID or %sACCESS_KEY_Id cannot be empty", configure.EnvPrefix, configure.EnvPrefix))

	os.Setenv(EnvVarAccessKeyIdNew, "")
	os.Setenv(EnvVarAccessKeyId, "AccessKeyId")
	c, err = p.resolve()
	assert.Nil(t, c)
	assert.EqualError(t, err, fmt.Sprintf("%sACCESS_KEY_SECRET cannot be empty", configure.EnvPrefix))
	os.Setenv(EnvVarAccessKeySecret, "AccessKeySecret")
	c, err = p.resolve()
	assert.Nil(t, err)
	assert.Equal(t, "access_key", tea.StringValue(c.Type))
	assert.Equal(t, "AccessKeyId", tea.StringValue(c.AccessKeyId))
	assert.Equal(t, "AccessKeySecret", tea.StringValue(c.AccessKeySecret))

	os.Setenv(EnvVarAccessKeyId, "AccessKeyId")
	os.Setenv(EnvVarAccessKeyIdNew, "AccessKeyIdNew")
	os.Setenv(EnvVarAccessKeySecret, "AccessKeySecret")
	c, err = p.resolve()
	assert.Nil(t, err)
	assert.Equal(t, "access_key", tea.StringValue(c.Type))
	assert.Equal(t, "AccessKeyIdNew", tea.StringValue(c.AccessKeyId))
	assert.Equal(t, "AccessKeySecret", tea.StringValue(c.AccessKeySecret))

	os.Setenv(configure.EnvPrefix+"SECURITY_TOKEN", "token")
	c, err = p.resolve()
	assert.Nil(t, err)
	assert.Equal(t, "sts", tea.StringValue(c.Type))
	assert.Equal(t, "AccessKeyIdNew", tea.StringValue(c.AccessKeyId))
	assert.Equal(t, "AccessKeySecret", tea.StringValue(c.AccessKeySecret))
	assert.Equal(t, "token", tea.StringValue(c.SecurityToken))
}
