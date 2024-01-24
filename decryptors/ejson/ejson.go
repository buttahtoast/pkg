package ejson

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shopify/ejson"
	"github.com/buttahtoast/pkg/decryptors"
	"k8s.io/client-go/kubernetes"
)

const (
	// PublicKeyField is the field name of the public key in the ejson
	PublicKeyField = "_public_key"
	// DecryptionEjsonExt is the extension of the file containing an ejson prviate key
	// file
	DecryptionEjsonExt = ".key"
)

type EjsonDecryptor struct {
	// stores all private keys for the decryptor
	keys []string
	// directory to search for ejson keys on disk
	keyDirectory string
	// Interface decryptor config
	Config decryptors.DecryptorConfig
}

// Initialize a new EJSON Decryptor
func NewEJSONDecryptor(config decryptors.DecryptorConfig, keyDirectory string, keys ...string) (*EjsonDecryptor, error) {
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
	if len(data) == 0 {
		return false, nil
	}

	var content map[string]interface{}
	content, err := decryptors.UnmarshalJSONorYAML(data)
	if err != nil {
		return false, fmt.Errorf("FAILED: %w", err)
	}

	f := content[PublicKeyField]
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
// Only keys within the secret with the extension .key
// will be loaded as ejson private keys
func (d *EjsonDecryptor) KeysFromSecret(secretName string, namespace string, client *kubernetes.Clientset, ctx context.Context) (err error) {
	keySecret, err := client.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return &decryptors.MissingKubernetesSecret{Secret: secretName, Namespace: namespace}
	} else if err != nil {
		return err
	}

	// Exract all keys from secret
	for name, value := range keySecret.Data {
		if filepath.Ext(name) == DecryptionEjsonExt {
			err := d.AddKey(string(value))
			if err != nil {
				return fmt.Errorf("failed to import data from %s decryption Secret '%s': %w", name, secretName, err)
			}
		}
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

	content, err = decryptors.UnmarshalJSONorYAML(data)
	if err != nil {
		return nil, fmt.Errorf("HELLO to unmarshal ejson: %w", err)
		//return nil, err
	}

	// Remove Public Key information
	delete(content, PublicKeyField)

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
