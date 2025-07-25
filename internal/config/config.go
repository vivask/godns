package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen    string        `yaml:"listen"`
	UP1       string        `yaml:"up1"`
	UP2       string        `yaml:"up2"`
	UP3       string        `yaml:"up3"`
	CacheSize int           `yaml:"cache_size"`
	Timeout   time.Duration `yaml:"timeout"`
	LogLevel  string        `yaml:"log_level"`
	Adblock   struct {
		Enable  bool
		Update  string
		Time    string
		Sources []string
	}
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
