package credentials

import "github.com/aliyun/credentials-go/configure"

// Environmental variables that may be used by the provider
const (
	ENVCredentialFile          = configure.EnvPrefix + "CREDENTIALS_FILE"
	ENVEcsMetadata             = configure.EnvPrefix + "ECS_METADATA"
	ENVEcsMetadataIMDSv2Enable = configure.EnvPrefix + "ECS_IMDSV2_ENABLE"
	PATHCredentialFile         = configure.PATHCredentialFile
	ENVRoleArn                 = configure.EnvPrefix + "ROLE_ARN"
	ENVOIDCProviderArn         = configure.EnvPrefix + "OIDC_PROVIDER_ARN"
	ENVOIDCTokenFile           = configure.EnvPrefix + "OIDC_TOKEN_FILE"
	ENVRoleSessionName         = configure.EnvPrefix + "ROLE_SESSION_NAME"
)

// Provider will be implemented When you want to customize the provider.
type Provider interface {
	resolve() (*Config, error)
}
