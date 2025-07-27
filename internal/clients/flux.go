/*
Copyright 2021 Upbound Inc.
*/

package clients

import (
	"context"
	"encoding/json"

	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/crossplane/upjet/pkg/terraform"

	"github.com/alanrichman/provider-flux/apis/v1beta1"
)

const (
	// error messages
	errNoProviderConfig     = "no providerConfigRef provided"
	errGetProviderConfig    = "cannot get referenced ProviderConfig"
	errTrackUsage           = "cannot track ProviderConfig usage"
	errExtractCredentials   = "cannot extract credentials"
	errUnmarshalCredentials = "cannot unmarshal flux credentials as JSON"

	// credential keys for Git authentication
	keyGitURL                   = "git_url"
	keyGitBranch                = "git_branch"
	keyGitAuthorName            = "git_author_name"
	keyGitAuthorEmail           = "git_author_email"
	keyGitCommitMessageAppendix = "git_commit_message_appendix"
	keyGitGPGKeyID              = "git_gpg_key_id"
	keyGitGPGKeyRing            = "git_gpg_key_ring"
	keyGitGPGPassphrase         = "git_gpg_passphrase"

	// Git HTTP authentication
	keyGitHTTPUsername             = "git_http_username"
	keyGitHTTPPassword             = "git_http_password"
	keyGitHTTPAllowInsecure        = "git_http_allow_insecure"
	keyGitHTTPCertificateAuthority = "git_http_certificate_authority"

	// Git SSH authentication
	keyGitSSHUsername     = "git_ssh_username"
	keyGitSSHPrivateKey   = "git_ssh_private_key"
	keyGitSSHPassword     = "git_ssh_password"
	keyGitSSHHostkeyAlgos = "git_ssh_hostkey_algos"

	// credential keys for Kubernetes authentication
	keyKubeHost                  = "kube_host"
	keyKubeUsername              = "kube_username"
	keyKubePassword              = "kube_password"
	keyKubeInsecure              = "kube_insecure"
	keyKubeClientCertificate     = "kube_client_certificate"
	keyKubeClientKey             = "kube_client_key"
	keyKubeClusterCACertificate  = "kube_cluster_ca_certificate"
	keyKubeConfigPath            = "kube_config_path"
	keyKubeConfigPaths           = "kube_config_paths"
	keyKubeConfigContext         = "kube_config_context"
	keyKubeConfigContextAuthInfo = "kube_config_context_auth_info"
	keyKubeConfigContextCluster  = "kube_config_context_cluster"
	keyKubeToken                 = "kube_token"
	keyKubeProxyURL              = "kube_proxy_url"
	keyKubeExecAPIVersion        = "kube_exec_api_version"
	keyKubeExecCommand           = "kube_exec_command"
	keyKubeExecArgs              = "kube_exec_args"
	keyKubeExecEnv               = "kube_exec_env"
)

// Helper functions for configuration building

// parseJSONArray parses a JSON string into a string slice
func parseJSONArray(value string) ([]string, error) {
	var result []string
	if err := json.Unmarshal([]byte(value), &result); err != nil {
		return nil, err
	}
	return result, nil
}

// parseJSONMap parses a JSON string into a string map
func parseJSONMap(value string) (map[string]string, error) {
	var result map[string]string
	if err := json.Unmarshal([]byte(value), &result); err != nil {
		return nil, err
	}
	return result, nil
}

// setStringValue sets a string value in config if the credential exists
func setStringValue(config map[string]any, configKey, credKey string, creds map[string]string) {
	if v, ok := creds[credKey]; ok {
		config[configKey] = v
	}
}

// setBoolValue sets a boolean value in config if the credential exists
func setBoolValue(config map[string]any, configKey, credKey string, creds map[string]string) {
	if v, ok := creds[credKey]; ok {
		config[configKey] = v == "true"
	}
}

// setJSONArrayValue sets a JSON array value in config if the credential exists and is valid JSON
func setJSONArrayValue(config map[string]any, configKey, credKey string, creds map[string]string) {
	if v, ok := creds[credKey]; ok {
		if arr, err := parseJSONArray(v); err == nil {
			config[configKey] = arr
		}
	}
}

// setJSONMapValue sets a JSON map value in config if the credential exists and is valid JSON
func setJSONMapValue(config map[string]any, configKey, credKey string, creds map[string]string) {
	if v, ok := creds[credKey]; ok {
		if m, err := parseJSONMap(v); err == nil {
			config[configKey] = m
		}
	}
}

// buildGitConfig builds the Git configuration section
func buildGitConfig(creds map[string]string) map[string]any {
	gitConfig := map[string]any{}

	// Basic Git settings
	setStringValue(gitConfig, "url", keyGitURL, creds)
	setStringValue(gitConfig, "branch", keyGitBranch, creds)
	setStringValue(gitConfig, "author_name", keyGitAuthorName, creds)
	setStringValue(gitConfig, "author_email", keyGitAuthorEmail, creds)
	setStringValue(gitConfig, "commit_message_appendix", keyGitCommitMessageAppendix, creds)
	setStringValue(gitConfig, "gpg_key_id", keyGitGPGKeyID, creds)
	setStringValue(gitConfig, "gpg_key_ring", keyGitGPGKeyRing, creds)
	setStringValue(gitConfig, "gpg_passphrase", keyGitGPGPassphrase, creds)

	// HTTP authentication
	httpConfig := buildHTTPConfig(creds)
	if len(httpConfig) > 0 {
		gitConfig["http"] = httpConfig
	}

	// SSH authentication
	sshConfig := buildSSHConfig(creds)
	if len(sshConfig) > 0 {
		gitConfig["ssh"] = sshConfig
	}

	return gitConfig
}

// buildHTTPConfig builds the HTTP authentication configuration
func buildHTTPConfig(creds map[string]string) map[string]any {
	httpConfig := map[string]any{}

	setStringValue(httpConfig, "username", keyGitHTTPUsername, creds)
	setStringValue(httpConfig, "password", keyGitHTTPPassword, creds)
	setBoolValue(httpConfig, "allow_insecure_http", keyGitHTTPAllowInsecure, creds)
	setStringValue(httpConfig, "certificate_authority", keyGitHTTPCertificateAuthority, creds)

	return httpConfig
}

// buildSSHConfig builds the SSH authentication configuration
func buildSSHConfig(creds map[string]string) map[string]any {
	sshConfig := map[string]any{}

	setStringValue(sshConfig, "username", keyGitSSHUsername, creds)
	setStringValue(sshConfig, "private_key", keyGitSSHPrivateKey, creds)
	setStringValue(sshConfig, "password", keyGitSSHPassword, creds)
	setJSONArrayValue(sshConfig, "hostkey_algos", keyGitSSHHostkeyAlgos, creds)

	return sshConfig
}

// buildKubernetesConfig builds the Kubernetes configuration section
func buildKubernetesConfig(creds map[string]string) map[string]any {
	kubeConfig := map[string]any{}

	// Basic Kubernetes settings
	setStringValue(kubeConfig, "host", keyKubeHost, creds)
	setStringValue(kubeConfig, "username", keyKubeUsername, creds)
	setStringValue(kubeConfig, "password", keyKubePassword, creds)
	setBoolValue(kubeConfig, "insecure", keyKubeInsecure, creds)
	setStringValue(kubeConfig, "client_certificate", keyKubeClientCertificate, creds)
	setStringValue(kubeConfig, "client_key", keyKubeClientKey, creds)
	setStringValue(kubeConfig, "cluster_ca_certificate", keyKubeClusterCACertificate, creds)
	setStringValue(kubeConfig, "config_path", keyKubeConfigPath, creds)
	setJSONArrayValue(kubeConfig, "config_paths", keyKubeConfigPaths, creds)
	setStringValue(kubeConfig, "config_context", keyKubeConfigContext, creds)
	setStringValue(kubeConfig, "config_context_auth_info", keyKubeConfigContextAuthInfo, creds)
	setStringValue(kubeConfig, "config_context_cluster", keyKubeConfigContextCluster, creds)
	setStringValue(kubeConfig, "token", keyKubeToken, creds)
	setStringValue(kubeConfig, "proxy_url", keyKubeProxyURL, creds)

	// Exec authentication
	execConfig := buildExecConfig(creds)
	if len(execConfig) > 0 {
		kubeConfig["exec"] = execConfig
	}

	return kubeConfig
}

// buildExecConfig builds the Kubernetes exec authentication configuration
func buildExecConfig(creds map[string]string) map[string]any {
	execConfig := map[string]any{}

	setStringValue(execConfig, "api_version", keyKubeExecAPIVersion, creds)
	setStringValue(execConfig, "command", keyKubeExecCommand, creds)
	setJSONArrayValue(execConfig, "args", keyKubeExecArgs, creds)
	setJSONMapValue(execConfig, "env", keyKubeExecEnv, creds)

	return execConfig
}

// TerraformSetupBuilder builds Terraform a terraform.SetupFn function which
// returns Terraform provider setup configuration
func TerraformSetupBuilder(version, providerSource, providerVersion string) terraform.SetupFn {
	return func(ctx context.Context, client client.Client, mg resource.Managed) (terraform.Setup, error) {
		ps := terraform.Setup{
			Version: version,
			Requirement: terraform.ProviderRequirement{
				Source:  providerSource,
				Version: providerVersion,
			},
		}

		configRef := mg.GetProviderConfigReference()
		if configRef == nil {
			return ps, errors.New(errNoProviderConfig)
		}

		pc := &v1beta1.ProviderConfig{}
		if err := client.Get(ctx, types.NamespacedName{Name: configRef.Name}, pc); err != nil {
			return ps, errors.Wrap(err, errGetProviderConfig)
		}

		t := resource.NewProviderConfigUsageTracker(client, &v1beta1.ProviderConfigUsage{})
		if err := t.Track(ctx, mg); err != nil {
			return ps, errors.Wrap(err, errTrackUsage)
		}

		data, err := resource.CommonCredentialExtractor(ctx, pc.Spec.Credentials.Source, client, pc.Spec.Credentials.CommonCredentialSelectors)
		if err != nil {
			return ps, errors.Wrap(err, errExtractCredentials)
		}

		creds := map[string]string{}
		if err := json.Unmarshal(data, &creds); err != nil {
			return ps, errors.Wrap(err, errUnmarshalCredentials)
		}

		// Build provider configuration
		ps.Configuration = map[string]any{}

		// Configure Git settings
		if gitConfig := buildGitConfig(creds); len(gitConfig) > 0 {
			ps.Configuration["git"] = gitConfig
		}

		// Configure Kubernetes settings
		if kubeConfig := buildKubernetesConfig(creds); len(kubeConfig) > 0 {
			ps.Configuration["kubernetes"] = kubeConfig
		}

		return ps, nil
	}
}
