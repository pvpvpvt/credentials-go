package configure

const (
	DefaultProfileName          = "default"
	StsDefaultEndpoint          = "{{sts_default_endpoint}}"
	DomainSuffix                = "{{endpoint_suffix}}"
	DefaultRegion               = "cn-hangzhou"
	ConfigStorePath             = "/{{config_path}}/config.json"
	EnvPrefix                   = "{{env_prefix}}"
	ECSIMDSSecurityCredURL      = "http://{{metadata_host}}/latest/meta-data/ram/security-credentials/"
	ECSIMDSSecurityCredTokenURL = "http://{{metadata_host}}/latest/api/token"
	ECSIMDSHeaderPrefix         = "{{imds_header_prefix}}"
	PATHCredentialFile          = "~/{{credential_file_path}}/credentials"
	SignPrefix                  = "{{sign_prefix}}"
	SignatureTypePrefix         = "{{signature_type_prefix}}"
)
