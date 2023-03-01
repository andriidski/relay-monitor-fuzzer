package api

type APIConfig struct {
	Host string `yaml:"host"`
	Port uint16 `yaml:"port"`
}

type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
