package credentials

import (
	"os"
	"testing"

	"github.com/aliyun/credentials-go/configure"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/credentials-go/credentials/internal/utils"
	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {
	config := new(Config)
	assert.Equal(t, "{\n   \"type\": null,\n   \"access_key_id\": null,\n   \"access_key_secret\": null,\n   \"security_token\": null,\n   \"bearer_token\": null,\n   \"oidc_provider_arn\": null,\n   \"oidc_token\": null,\n   \"role_arn\": null,\n   \"role_session_name\": null,\n   \"role_session_expiration\": null,\n   \"policy\": null,\n   \"external_id\": null,\n   \"sts_endpoint\": null,\n   \"role_name\": null,\n   \"enable_imds_v2\": null,\n   \"disable_imds_v1\": null,\n   \"metadata_token_duration\": null,\n   \"url\": null,\n   \"session_expiration\": null,\n   \"public_key_id\": null,\n   \"private_key_file\": null,\n   \"host\": null,\n   \"timeout\": null,\n   \"connect_timeout\": null,\n   \"proxy\": null,\n   \"inAdvanceScale\": null\n}", config.String())
	assert.Equal(t, "{\n   \"type\": null,\n   \"access_key_id\": null,\n   \"access_key_secret\": null,\n   \"security_token\": null,\n   \"bearer_token\": null,\n   \"oidc_provider_arn\": null,\n   \"oidc_token\": null,\n   \"role_arn\": null,\n   \"role_session_name\": null,\n   \"role_session_expiration\": null,\n   \"policy\": null,\n   \"external_id\": null,\n   \"sts_endpoint\": null,\n   \"role_name\": null,\n   \"enable_imds_v2\": null,\n   \"disable_imds_v1\": null,\n   \"metadata_token_duration\": null,\n   \"url\": null,\n   \"session_expiration\": null,\n   \"public_key_id\": null,\n   \"private_key_file\": null,\n   \"host\": null,\n   \"timeout\": null,\n   \"connect_timeout\": null,\n   \"proxy\": null,\n   \"inAdvanceScale\": null\n}", config.GoString())

	config.SetStsEndpoint("sts.cn-hangzhou." + configure.DomainSuffix)
	assert.Equal(t, "sts.cn-hangzhou."+configure.DomainSuffix, *config.StsEndpoint)
}

func TestNewCredentialWithNil(t *testing.T) {
	rollback := utils.Memory(configure.EnvPrefix+"ACCESS_KEY_ID", configure.EnvPrefix+"ACCESS_KEY_SECRET", configure.EnvPrefix+"CLI_PROFILE_DISABLED")
	defer func() {
		rollback()
	}()

	os.Setenv(configure.EnvPrefix+"ACCESS_KEY_ID", "accesskey")
	os.Setenv(configure.EnvPrefix+"ACCESS_KEY_SECRET", "accesssecret")

	cred, err := NewCredential(nil)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	os.Unsetenv(configure.EnvPrefix + "ACCESS_KEY_ID")
	os.Unsetenv(configure.EnvPrefix + "ACCESS_KEY_SECRET")
	os.Setenv(configure.EnvPrefix+"CLI_PROFILE_DISABLED", "true")

	cred, err = NewCredential(nil)
	assert.Nil(t, err)
	_, err = cred.GetCredential()
	assert.Contains(t, err.Error(), "unable to get credentials from any of the providers in the chain:")
}

func TestNewCredentialWithAK(t *testing.T) {
	config := new(Config)
	config.SetType("access_key")
	cred, err := NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "the access key id is empty", err.Error())
	assert.Nil(t, cred)

	config.SetAccessKeyId("AccessKeyId")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "the access key secret is empty", err.Error())
	assert.Nil(t, cred)

	config.SetAccessKeySecret("AccessKeySecret")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	cm, err := cred.GetCredential()
	assert.Nil(t, err)
	assert.Equal(t, "AccessKeyId", *cm.AccessKeyId)
	assert.Equal(t, "AccessKeySecret", *cm.AccessKeySecret)
	assert.Equal(t, "", *cm.SecurityToken)

}

func TestNewCredentialWithSts(t *testing.T) {
	config := new(Config)
	config.SetType("sts")

	config.SetAccessKeyId("")
	cred, err := NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "the access key id is empty", err.Error())
	assert.Nil(t, cred)

	config.SetAccessKeyId("akid")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "the access key secret is empty", err.Error())
	assert.Nil(t, cred)

	config.SetAccessKeySecret("aksecret")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "the security token is empty", err.Error())
	assert.Nil(t, cred)

	config.SetSecurityToken("SecurityToken")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)
}

func TestNewCredentialWithECSRAMRole(t *testing.T) {
	config := new(Config)
	config.SetType("ecs_ram_role")
	cred, err := NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.SetRoleName("AccessKeyId")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.SetDisableIMDSv1(false)
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.SetDisableIMDSv1(true)
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)
}

func TestNewCredentialWithRAMRoleARN(t *testing.T) {
	config := new(Config)
	config.SetType("ram_role_arn")
	config.SetAccessKeyId("")
	cred, err := NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "the access key id is empty", err.Error())
	assert.Nil(t, cred)

	config.SetAccessKeyId("akid")
	config.SetAccessKeySecret("")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "the access key secret is empty", err.Error())
	assert.Nil(t, cred)

	config.SetAccessKeySecret("AccessKeySecret")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "the RoleArn is empty", err.Error())
	assert.Nil(t, cred)

	config.SetRoleArn("roleArn")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.SetRoleSessionName("role_session_name")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	// empty security token should ok
	config.SetSecurityToken("")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	// with sts should ok
	config.SetSecurityToken("securitytoken")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

	config.SetExternalId("externalId")
	config.SetPolicy("policy")
	config.SetRoleSessionExpiration(3600)
	config.SetRoleSessionName("roleSessionName")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)

}

func TestNewCredentialWithBearerToken(t *testing.T) {
	config := new(Config)
	config.SetType("bearer")
	cred, err := NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "BearerToken cannot be empty", err.Error())
	assert.Nil(t, cred)

	config.SetBearerToken("BearerToken")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)
}

func TestNewCredentialWithOIDC(t *testing.T) {
	config := new(Config)
	// oidc role arn
	config.SetType("oidc_role_arn")
	cred, err := NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "the OIDCTokenFilePath is empty", err.Error())
	assert.Nil(t, cred)

	config.SetOIDCTokenFilePath("oidc_token_file_path_test")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "the OIDCProviderARN is empty", err.Error())
	assert.Nil(t, cred)

	config.SetOIDCProviderArn("oidc_provider_arn_test")
	cred, err = NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "the RoleArn is empty", err.Error())
	assert.Nil(t, cred)

	config.SetRoleArn("role_arn_test")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)
	assert.Equal(t, "oidc_provider_arn_test", tea.StringValue(config.OIDCProviderArn))
	assert.Equal(t, "oidc_token_file_path_test", tea.StringValue(config.OIDCTokenFilePath))
	assert.Equal(t, "role_arn_test", tea.StringValue(config.RoleArn))
}

func TestNewCredentialWithCredentialsURI(t *testing.T) {
	config := new(Config)

	config.SetType("credentials_uri").
		SetURLCredential("http://test/")
	cred, err := NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)
	assert.Equal(t, "http://test/", tea.StringValue(config.Url))

	config.SetURLCredential("")
	cred, err = NewCredential(config)
	assert.Nil(t, err)
	assert.NotNil(t, cred)
	assert.Equal(t, "", tea.StringValue(config.Url))
}

func TestNewCredentialWithInvalidType(t *testing.T) {
	config := new(Config)
	config.SetType("sdk")
	cred, err := NewCredential(config)
	assert.NotNil(t, err)
	assert.Equal(t, "invalid type option, support: access_key, sts, bearer, ecs_ram_role, ram_role_arn, rsa_key_pair, oidc_role_arn, credentials_uri", err.Error())
	assert.Nil(t, cred)
}
