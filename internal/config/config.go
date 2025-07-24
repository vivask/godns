package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen    string        `yaml:"listen"`
	DNS1      string        `yaml:"dns1"`
	DNS2      string        `yaml:"dns2"`
	DNS3      string        `yaml:"dns3"`
	CacheSize int           `yaml:"cache_size"`
	Timeout   time.Duration `yaml:"timeout"`
	LogLevel  string        `yaml:"log_level"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
