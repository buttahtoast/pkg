package decryptors

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

type MissingKubernetesSecret struct {
	Secret    string
	Namespace string
}

func (e *MissingKubernetesSecret) Error() string {
	return fmt.Sprintf("Secret not found: %s/%s", e.Namespace, e.Secret)
}

func UnmarshalJSONorYAML(data []byte) (map[string]interface{}, error) {
	var result map[string]interface{}
	err := json.Unmarshal(data, &result)
	if err != nil {
		err = yaml.Unmarshal(data, &result)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
