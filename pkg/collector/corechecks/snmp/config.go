package snmp

import (
	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"gopkg.in/yaml.v2"
)

type metricsConfig struct {
	OID  string `yaml:"OID"`
	Name string `yaml:"name"`
}

type snmpInitConfig struct {
	OidBatchSize             int `yaml:"oid_batch_size"`
	RefreshOidsCacheInterval int `yaml:"refresh_oids_cache_interval"`
	// TODO: To implement:
	// - global_metrics
	// - profiles
}

type snmpInstanceConfig struct {
	IPAddress       string          `yaml:"ip_address"`
	Port            int             `yaml:"port"`
	CommunityString string          `yaml:"community_string"`
	SnmpVersion     string          `yaml:"snmp_version"`
	Timeout         int             `yaml:"timeout"`
	Retries         int             `yaml:"retries"`
	User            string          `yaml:"user"`
	AuthProtocol    string          `yaml:"authProtocol"`
	AuthKey         string          `yaml:"authKey"`
	PrivProtocol    string          `yaml:"privProtocol"`
	PrivKey         string          `yaml:"privKey"`
	ContextName     string          `yaml:"context_name"`
	Metrics         []metricsConfig `yaml:"metrics"`
	// TODO: To implement:
	//   - context_engine_id: Investigate if we can remove this configuration.
	//   - use_global_metrics
	//   - profile
	//   - metrics
	//   - metric_tags
}

type snmpConfig struct {
	IPAddress       string
	Port            int
	CommunityString string
	SnmpVersion     string
	Timeout         int
	Retries         int
	User            string
	AuthProtocol    string
	AuthKey         string
	PrivProtocol    string
	PrivKey         string
	ContextName     string
	Metrics         []metricsConfig
}

func buildConfig(rawInstance integration.Data, rawInitConfig integration.Data) (snmpConfig, error) {
	instance := snmpInstanceConfig{}
	init := snmpInitConfig{}

	err := yaml.Unmarshal(rawInitConfig, &init)
	if err != nil {
		return snmpConfig{}, err
	}

	err = yaml.Unmarshal(rawInstance, &instance)
	if err != nil {
		return snmpConfig{}, err
	}

	c := snmpConfig{}
	c.IPAddress = instance.IPAddress
	c.Port = instance.Port
	c.Metrics = instance.Metrics

	return c, err
}