package decryptors

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shopify/ejson"
	"k8s.io/client-go/kubernetes"
)

const (
	publicKeyField = "_public_key"
)

type EjsonDecryptor struct {
	// stores all private keys for the decryptor
	keys []string

	// directory to search for ejson keys on disk
	keyDirectory string
	// Interface decryptor config
	Config DecryptorConfig
}

// Initialize a new EJSON Decryptor
func NewEJSONDecryptor(config DecryptorConfig, keyDirectory string, keys ...string) (*EjsonDecryptor, error) {
	init := &EjsonDecryptor{
		keys:         []string{},
		keyDirectory: keyDirectory,
		Config:       config,
	}

	if len(keys) > 0 {
		for _, key := range keys {
			init.AddKey(key)
		}
	}

	err := init.findPrivateKeysFromDisk()
	if err != nil {
		return nil, err
	}

	return init, nil
}

func (d *EjsonDecryptor) IsEncrypted(data []byte) (bool, error) {
	var jdata map[string]interface{}
	err := json.Unmarshal(data, &jdata)
	if err != nil {
		return false, err
	}
	f := jdata[publicKeyField]
	if f == nil || f == "" {
		return false, nil
	}
	return true, nil
}

func (d *EjsonDecryptor) AddKey(key string) error {
	privkeyBytes, err := hex.DecodeString(strings.TrimSpace(key))
	if err != nil {
		return err
	}

	if len(privkeyBytes) != 32 {
		return fmt.Errorf("invalid private key length: %v", privkeyBytes)
	}

	d.keys = append(d.keys, strings.TrimSpace(key))
	return nil
}

// Load Keys from Kubernetes Secret
func (d *EjsonDecryptor) KeysFromSecret(secretName string, namespace string, client *kubernetes.Clientset, ctx context.Context) (err error) {
	kubernetesSecret, err := client.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return &MissingKubernetesSecret{Secret: secretName, Namespace: namespace}
	} else if err != nil {
		return err
	}

	// Exract all keys from secret
	for s := range kubernetesSecret.Data {
		key := string(kubernetesSecret.Data[s])
		d.AddKey(key)
	}

	return nil
}

// Read an ejson file
// Skip decryption still removes the publicKeyField
func (d *EjsonDecryptor) Decrypt(data []byte) (content map[string]interface{}, err error) {
	if !d.Config.SkipDecrypt {
		data, err = d.read(data)
		if err != nil {
			return nil, err
		}
	}

	err = json.Unmarshal(data, &content)
	if err != nil {
		return nil, err
	}

	// Remove Public Key information
	delete(content, publicKeyField)

	return content, err
}

// Attempts to decrypt an ejson file with the given keys
func (d *EjsonDecryptor) read(data []byte) (content []byte, err error) {
	var outputBuffer bytes.Buffer

	decrypted := false
	f := bytes.NewReader(data)
	if !d.Config.SkipDecrypt {

		// Try all loaded keys
		for key := range d.keys {
			err = ejson.Decrypt(f, &outputBuffer, "", string(d.keys[key]))
			if err != nil {
				continue
			} else {
				decrypted = true
				break
			}
		}

		// Check if file was decrypted (and must be)
		if !decrypted {
			e := fmt.Errorf("could not decrypt with given keys")
			// This error happens, if the file is not properly encrypted (or not encrypted at all)
			// Considered an error.
			if err != nil && err.Error() == "invalid message format" {
				e = fmt.Errorf("content is not encrypted with ejson (%s)", err)
			}
			return nil, e
		}
	}

	if outputBuffer.Bytes() != nil {
		return outputBuffer.Bytes(), nil
	}

	return data, nil
}

func (d *EjsonDecryptor) findPrivateKeysFromDisk() error {
	if _, err := os.Stat(d.keyDirectory); os.IsNotExist(err) {
		fmt.Printf("Key directory %s does not exist, skipping\n", d.keyDirectory)
		return nil
	}
	files, err := os.ReadDir(d.keyDirectory)
	if err != nil {
		return err
	}

	// Regular expression to match filenames of format [32]byte
	// Considering filenames to be hex encoded strings
	r := regexp.MustCompile("^[a-fA-F0-9]{64}$")

	for _, file := range files {
		if !file.IsDir() && r.MatchString(file.Name()) {
			// Step 4: Read the content of the matching files
			content, err := os.ReadFile(d.keyDirectory + "/" + file.Name())
			if err != nil {
				return err
			}
			err = d.AddKey(string(content))
			if err != nil {
				return err
			}
		}
	}

	return nil
}
