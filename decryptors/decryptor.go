package decryptors

import (
	"context"

	"k8s.io/client-go/kubernetes"
)

type DecryptorConfig struct {
	// Decryption is skipped, but decryption metadata is removed
	SkipDecrypt bool
}

type Decryptor interface {
	// Checks if given content is encrypted by the decryptor interface
	IsEncrypted(data []byte) (bool, error)
	// Reads the given content, based on the decrypter config attempts to decrypt
	Decrypt(data []byte) (content map[string]interface{}, err error)
	// Read Private Keys from kubernetes secret
	KeysFromSecret(secretName string, namespace string, client *kubernetes.Clientset, ctx context.Context) (err error)
}
