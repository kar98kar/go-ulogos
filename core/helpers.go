// +build !windows

package core

import (
	"fmt"
	"io"

	"github.com/kar98kar/go-ulogos/core/assets"
)

func assetsOpen(path string) (io.ReadCloser, error) {
	file, err := assets.DEFAULTS.Open(path)
	if err != nil {
		err = fmt.Errorf("Error opening '%s' default JSON: %v", path, err)
	}
	return file, err
}
