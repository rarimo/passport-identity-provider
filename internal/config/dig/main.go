package dig

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"

	figure "gitlab.com/distributed_lab/figure/v3"
)

const (
	digKey      = "dig"
	requiredTag = "required"
	clearTag    = "clear"
)

var specTagsNum = len([]string{
	requiredTag,
	clearTag,
})

var validEnvName, _ = regexp.Compile("[a-zA-Z_]{1,}[a-zA-Z0-9_]{0,}")

var (
	ErrNotValidValue      = errors.New("not valid value")
	ErrNotValidTags       = errors.New("some tags are not valid")
	ErrInvalidEnvVarName  = errors.New("The environment variable is not valid")
	ErrEnvVarDoesNotExist = errors.New("The given enviroment variable does not exist")
)

type Field struct {
	isRequired bool
	needClear  bool
	envVar     string
	pValue     reflect.Value
}

type Digger struct {
	figurator *figure.Figurator
	hooks     figure.Hooks
	what      interface{}
	fields    []Field
}

func Out(target interface{}) *Digger {
	return &Digger{
		figurator: figure.Out(target),
		what:      target,
		fields:    getFields(reflect.ValueOf(target).Elem(), target),
	}
}

func (d *Digger) Where(values map[string]interface{}) *Digger {
	d.figurator = d.figurator.From(values)
	return d
}

func (d *Digger) With(hooks ...figure.Hooks) *Digger {
	merged := d.hooks
	for _, partial := range hooks {
		for key, hook := range partial {
			merged[key] = hook
		}
	}
	d.hooks = merged

	d.figurator = d.figurator.With(hooks...)

	return d
}

func (d *Digger) Now() error {
	if err := d.figurator.Please(); err != nil {
		return err
	}

	return d.setValues()
}

func getFields(vf reflect.Value, target interface{}) []Field {
	if vf.Kind() != reflect.Struct {
		panic("A target must be a struct")
	}

	fields := make([]Field, 0)
	for i := 0; i < vf.NumField(); i++ {
		fieldTag := vf.Type().Field(i).Tag.Get(digKey)
		if len(fieldTag) == 0 {
			continue
		}

		field := getField(fieldTag)

		field.pValue = vf.Field(i)

		fields = append(fields, field)
	}

	return fields
}

func getField(fieldTag string) Field {
	tags := strings.Split(fieldTag, ",")

	if len(tags) == 0 || len(tags) > specTagsNum+2 {
		panic(ErrNotValidTags)
	}

	match := validEnvName.FindString(tags[0])
	if match == "" {
		panic(ErrInvalidEnvVarName)
	}

	field := Field{
		envVar: match,
	}

	if len(tags) == 1 {
		return field
	}

	for _, tag := range tags[1:] {
		switch tag {
		case requiredTag:
			field.isRequired = true
		case clearTag:
			field.needClear = true
		default:
			panic(ErrNotValidTags)
		}
	}

	return field
}

func (d *Digger) setValues() error {
	for _, field := range d.fields {
		if err := d.setValue(&field); err != nil {
			return err
		}
	}

	return nil
}

func (d *Digger) setValue(field *Field) error {
	value, found := lookupEnv(field.envVar, field.needClear)
	if !found {
		if field.isRequired {
			return errors.Wrap(ErrEnvVarDoesNotExist, "Env var is required", logan.F{
				"env_var": field.envVar,
			})
		}

		return nil
	}

	hook, hasHook := d.hooks[field.pValue.Type().String()]
	if hasHook {
		val, err := hook(value)
		if err != nil {
			return err
		}
		field.pValue.Set(val)
		return nil
	}

	var err error
	switch field.pValue.Kind() {
	case reflect.Bool:
		err = setBool(field.pValue, value)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		err = setInt(field.pValue, value)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		err = setUint(field.pValue, value)
	case reflect.Float32, reflect.Float64:
		err = setFloat(field.pValue, value)
	case reflect.String:
		err = setString(field.pValue, value)
	default:
		return errors.New(fmt.Sprintf("%s types are not supported", field.pValue.Type().String()))
	}

	if err != nil {
		return nil
	}

	return nil
}

func setBool(vv reflect.Value, value string) error {
	v, err := strconv.ParseBool(value)
	vv.SetBool(v)
	return err
}

func setInt(vv reflect.Value, value string) error {
	v, err := strconv.ParseInt(value, 0, 0)
	vv.SetInt(v)
	return err
}

func setUint(vv reflect.Value, value string) error {
	v, err := strconv.ParseUint(value, 0, 64)
	vv.SetUint(v)
	return err
}

func setFloat(vv reflect.Value, value string) error {
	v, err := strconv.ParseFloat(value, 64)
	vv.SetFloat(v)
	return err
}

func setString(vv reflect.Value, value string) error {
	vv.SetString(value)
	return nil
}

func lookupEnv(key string, needClear bool) (string, bool) {
	value, found := os.LookupEnv(key)
	if found && needClear {
		os.Unsetenv(key)
	}

	return value, found
}
