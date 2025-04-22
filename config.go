package main

import (
	"flag"
	"fmt"

	"github.com/ilyakaznacheev/cleanenv"
)

func ConfigLoader() *AppConfig {
	var config AppConfig
	cfgPath := *flag.String("CONFIG", "config.yml", "Path to application config file")
	err := cleanenv.ReadConfig(cfgPath, &config)
	if err != nil {
		panic(fmt.Sprintf("Unable to load config file %s. Error: %s", cfgPath, err))
	}
	return &config
}
