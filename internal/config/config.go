package config

import (
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"
	"html/template"

	log "github.com/sirupsen/logrus"
	"github.com/mitchellh/mapstructure"
)

// StringToLogLevelHookFunc returns a mapstructure.DecodeHookFunc which parses a logrus Level from a string
func StringToLogLevelHookFunc() mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String || t != reflect.TypeOf(log.InfoLevel) {
			return data, nil
		}

		var level log.Level
		err := level.UnmarshalText([]byte(data.(string)))
		return level, err
	}
}

// StringToTemplateHookFunc returns a mapstructure.DecodeHookFunc which parses a template.Template from a string
func StringToTemplateHookFunc() mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String || t.Kind() != reflect.TypeOf(template.Template{}).Kind() {
			return data, nil
		}

		return template.New("anonymous").Parse(data.(string))
	}
}

// DecoderOptions enables necessary mapstructure decode hook functions
func DecoderOptions(config *mapstructure.DecoderConfig) {
	config.ErrorUnused = true
	config.DecodeHook = mapstructure.ComposeDecodeHookFunc(
		config.DecodeHook,
		mapstructure.StringToTimeDurationHookFunc(),
		StringToLogLevelHookFunc(),
		StringToTemplateHookFunc(),
	)
}

// Config describes the configuration for Server
type Config struct {
	LogLevel log.Level `mapstructure:"log_level"`

	HTTP struct {
		ListenAddress string `mapstructure:"listen_address"`
		ListenPort string `mapstructure:"listen_port"`
		Secure bool `mapstructure:"secure"`

		CORS struct {
			AllowedOrigins []string `mapstructure:"allowed_origins"`
		}
	}

	SMTP struct {
		Host string `mapstructure:"host"`
		Port string `mapstructure:"port"`
		Username string `mapstructure:"username"`
		Password string `mapstructure:"password"`
		AccountAddress string `mapstructure:"account_address"`
		DashboardAddress string `mapstructure:"dashboard_address"`
	}

	SocsPortal struct {
		URL string `mapstructure:"url"`
		SingleMethod string `mapstructure:"single_method"`
		AllMethod string `mapstructure:"all_method"`
		Password string `mapstructure:"password"`
		Username string `mapstructure:"username"`
		SearchByOption string `mapstructure:"search_by_option"`
	}

	JWT struct {
		PublicKeyPath string `mapstructure:"public_key_path"`
		PrivateKeyPath string `mapstructure:"private_key_path"`
		PrivateKeyPassword string `mapstructure:"private_key_password"`
	}

	LDAP struct {
		URL string `mapstructure:"url"`
		DN string `mapstructure:"dn"`
		BindUser string `mapstructure:"bind_user"`
		BindSecret string `mapstructure:"bind_secret"`
		UserOU string `mapstructure:"user_ou"`
		SocietyOU string `mapstructure:"society_ou"`
		UserAttributes []string `mapstructure:"user_attributes"`
		SocietyAttributes []string `mapstructure:"society_attributes"`
		GroupAttributes []string `mapstructure:"group_attributes"`
	}

	CompSocSSO struct {
		AuthURL string `mapstructure:"auth_url"`
		TokenURL string `mapstructure:"token_url"`
		Picture string `mapstructure:"picture"`
		FriendlyName string `mapstructure:"friendly_name"`
		Description string `mapstructure:"description"`
		ClientID string `mapstructure:"client_id"`
		ClientSecret string `mapstructure:"client_secret"`
	}

	GoogleSSO struct {
		AuthURL string `mapstructure:"auth_url"`
		TokenURL string `mapstructure:"token_url"`
		FriendlyName string `mapstructure:"friendly_name"`
		Description string `mapstructure:"description"`
		Scope string `mapstructure:"scope"`
		ClientID string `mapstructure:"client_id"`
		ClientSecret string `mapstructure:"client_secret"`
	}
}

func (c *Config) FormHomeURL() string {
	var url string
	if c.HTTP.Secure {
		url += "https://"
	} else {
		url += "http://"
	}
	url += c.HTTP.ListenAddress
	return url
}

func loadSecret(parent interface{}, field string) error {
	v := reflect.ValueOf(parent).Elem()
	t := v.Type()
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("%v is not a struct", t.Name())
	}

	if _, ok := t.FieldByName(field); !ok {
		return fmt.Errorf("%v field %v not found", t.Name(), field)
	}
	f := v.FieldByName(field)

	if _, ok := t.FieldByName(field + "File"); !ok {
		return fmt.Errorf("%v file field %v not found", t.Name(), field)
	}
	fileField := v.FieldByName(field + "File")

	if fileField.Kind() != reflect.String {
		return fmt.Errorf("%v file field %v is not a string", t.Name(), fileField)
	}

	file := fileField.String()
	if file == "" {
		return nil
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read %v for field %v", file, field)
	}

	if f.Kind() == reflect.String {
		f.SetString(strings.TrimSpace(string(data)))
	} else if t == reflect.SliceOf(reflect.TypeOf(byte(0))) {
		f.SetBytes(data)
	} else {
		return fmt.Errorf("invalid type %v for field %v", t, field)
	}

	return nil
}