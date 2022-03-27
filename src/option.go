package step

import (
	"fmt"
	"os"
	"strings"
)

type Option struct {
	Directory       string `yaml:"Directory"`       // data directory
	DataFileMaxSize int64  `yaml:"DataFileMaxSize"` // data file max size
	Enable          bool   `yaml:"Enable"`          // data whether to enable encryption
	Secret          string `yaml:"Secret"`          // data encryption key
}

var (
	// DefaultOption default initialization option
	DefaultOption = Option{
		Directory:       "./data",
		DataFileMaxSize: 10240,
	}
)

// Validation 做一些初始化工作
func (o *Option) Validation() {

	// 目录为空的情况
	if o.Directory == "" {
		panic("The data file directory cannot be empty!!!")
	}

	// 判断字符串是否以 / 结尾
	o.Directory = pathBackslashes(o.Directory)

	// 剔除路径前后的空格
	o.Directory = strings.TrimSpace(o.Directory)

	// 初始化数据根目录
	Root = o.Directory

	// 初始化文件最大尺寸
	if o.DataFileMaxSize != 0 {
		defaultMaxFileSize = o.DataFileMaxSize
	}

	// 是否启用加密功能
	if o.Enable {
		if len(o.Secret) < 16 && len(o.Secret) > 16 {
			panic("The encryption key contains less than 16 characters!!!")
		}
		Secret = []byte(o.Secret)
		encoder = AES()
	}

	dataDirectory = fmt.Sprintf("%sdata/", Root)

	indexDirectory = fmt.Sprintf("%sindex/", Root)
}

// 判断字符串是否以 / 结尾
func pathBackslashes(path string) string {
	if !strings.HasSuffix(path, "/") {
		return fmt.Sprintf("%s/", path)
	}
	return path
}

// 检查目标路径是否存在
func pathExists(path string) (bool, error) {
	// 如果文件存在返回一个 FileInfo
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
