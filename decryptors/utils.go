package decryptors

import (
	"fmt"
	"os"
	"path/filepath"
)

type MissingKubernetesSecret struct {
	Secret    string
	Namespace string
}

func (e *MissingKubernetesSecret) Error() string {
	return fmt.Sprintf("Secret not found: %s/%s", e.Namespace, e.Secret)
}

func testdataPath() string {
	basePath, _ := os.Getwd()
	hackDirPath := filepath.Join(basePath, "testdata")
	return hackDirPath
}
