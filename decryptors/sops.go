package decryptors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fluxcd/kustomize-controller/internal/sops/age"
	"github.com/fluxcd/kustomize-controller/internal/sops/awskms"
	"github.com/fluxcd/kustomize-controller/internal/sops/azkv"
	intkeyservice "github.com/fluxcd/kustomize-controller/internal/sops/keyservice"
	"github.com/fluxcd/kustomize-controller/internal/sops/pgp"
	"go.etcd.io/etcd/client"
	"go.mozilla.org/sops/keyservice"
	"go.mozilla.org/sops/v3"
	"go.mozilla.org/sops/v3/aes"
	"go.mozilla.org/sops/v3/cmd/sops/common"
	"go.mozilla.org/sops/v3/cmd/sops/formats"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// DecryptionProviderSOPS is the SOPS provider name.
	DecryptionProviderSOPS = "sops"
	// DecryptionPGPExt is the extension of the file containing an armored PGP
	// key.
	DecryptionPGPExt = ".asc"
	// DecryptionAgeExt is the extension of the file containing an age key
	// file.
	DecryptionAgeExt = ".agekey"
	// DecryptionVaultTokenFileName is the name of the file containing the
	// Hashicorp Vault token.
	DecryptionVaultTokenFileName = "sops.vault-token"
	// DecryptionAWSKmsFile is the name of the file containing the AWS KMS
	// credentials.
	DecryptionAWSKmsFile = "sops.aws-kms"
	// DecryptionAzureAuthFile is the name of the file containing the Azure
	// credentials.
	DecryptionAzureAuthFile = "sops.azure-kv"
	// DecryptionGCPCredsFile is the name of the file containing the GCP
	// credentials.
	DecryptionGCPCredsFile = "sops.gcp-kms"
	// maxEncryptedFileSize is the max allowed file size in bytes of an encrypted
	// file.
	maxEncryptedFileSize int64 = 5 << 20
	// unsupportedFormat is used to signal no sopsFormatToMarkerBytes format was
	// detected by detectFormatFromMarkerBytes.
	unsupportedFormat = formats.Format(-1)
)

var (
	// sopsFormatToString is the counterpart to
	// https://github.com/mozilla/sops/blob/v3.7.2/cmd/sops/formats/formats.go#L16
	sopsFormatToString = map[formats.Format]string{
		formats.Binary: "binary",
		formats.Dotenv: "dotenv",
		formats.Ini:    "INI",
		formats.Json:   "JSON",
		formats.Yaml:   "YAML",
	}
	// sopsFormatToMarkerBytes contains a list of formats and their byte
	// order markers, used to detect if a Secret data field is SOPS' encrypted.
	sopsFormatToMarkerBytes = map[formats.Format][]byte{
		// formats.Binary is a JSON envelop at encrypted rest
		formats.Binary: []byte("\"mac\": \"ENC["),
		formats.Dotenv: []byte("sops_mac=ENC["),
		formats.Ini:    []byte("[sops]"),
		formats.Json:   []byte("\"mac\": \"ENC["),
		formats.Yaml:   []byte("mac: ENC["),
	}
)

// Decryptor performs decryption operations for a v1.Kustomization.
// The only supported decryption provider at present is
// DecryptionProviderSOPS.
type SOPSDecryptor struct {
	// client is the Kubernetes client used to e.g. retrieve Secrets with.
	client client.Client
	// maxFileSize is the max size in bytes a file is allowed to have to be
	// decrypted. Defaults to maxEncryptedFileSize.
	maxFileSize int64
	// checkSopsMac instructs the decryptor to perform the SOPS data integrity
	// check using the MAC. Not enabled by default, as arbitrary data gets
	// injected into most resources, causing the integrity check to fail.
	// Mostly kept around for feature completeness and documentation purposes.
	checkSopsMac bool

	// gnuPGHome is the absolute path of the GnuPG home directory used to
	// decrypt PGP data. When empty, the systems' GnuPG keyring is used.
	// When set, ImportKeys() imports found PGP keys into this keyring.
	gnuPGHome pgp.GnuPGHome
	// ageIdentities is the set of age identities available to the decryptor.
	ageIdentities age.ParsedIdentities
	// vaultToken is the Hashicorp Vault token used to authenticate towards
	// any Vault server.
	vaultToken string
	// awsCredsProvider is the AWS credentials provider object used to authenticate
	// towards any AWS KMS.
	awsCredsProvider *awskms.CredsProvider
	// azureToken is the Azure credential token used to authenticate towards
	// any Azure Key Vault.
	azureToken *azkv.Token
	// gcpCredsJSON is the JSON credential file of the service account used to
	// authenticate towards any GCP KMS.
	gcpCredsJSON []byte

	// keyServices are the SOPS keyservice.KeyServiceClient's available to the
	// decryptor.
	keyServices      []keyservice.KeyServiceClient
	localServiceOnce sync.Once

	// Interface decryptor config
	Config DecryptorConfig
}

// NewDecryptor creates a new Decryptor for the given kustomization.
// gnuPGHome can be empty, in which case the systems' keyring is used.
func NewSOPSDecryptor(maxFileSize int64, gnuPGHome string) *SOPSDecryptor {
	gnuPGHome, err := pgp.NewGnuPGHome()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create decryptor: %w", err)
	}
	return &SOPSDecryptor{
		maxFileSize: maxFileSize,
		gnuPGHome:   pgp.GnuPGHome(gnuPGHome),
	}
}

// NewTempDecryptor creates a new Decryptor, with a temporary GnuPG
// home directory to Decryptor.ImportKeys() into.
func NewTempDecryptor() (*SOPSDecryptor, func(), error) {
	gnuPGHome, err := pgp.NewGnuPGHome()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create decryptor: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(gnuPGHome.String()) }
	return NewSOPSDecryptor(maxEncryptedFileSize, gnuPGHome.String()), cleanup, nil
}

// IsEncrypted returns true if the given data is encrypted by SOPS.
func (d *SOPSDecryptor) IsEncrypted(data []byte) (bool, error) {
	var jdata map[string]interface{}
	err := json.Unmarshal(data, &jdata)
	if err != nil {
		return false, err
	}
	sopsField := jdata["sops"]
	if sopsField == nil || sopsField == "" {
		return false, nil
	}
	return true, nil
}

// AddGPGKey adds given GPG key to the decryptor's keyring.
func (d *SOPSDecryptor) AddGPGKey(key []byte) error {
	return d.gnuPGHome.Import(key)
}

// AddAgeKey to the decryptor's identities.
func (d *SOPSDecryptor) AddAgeKey(key []byte) {
	return d.ageIdentities.Import(string(key))
}

func (d *SOPSDecryptor) KeysFromSecret(secretName string, namespace string, client *kubernetes.Clientset, ctx context.Context) (err error) {
	// Retrieve Secret
	keySecret, err := client.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return &MissingKubernetesSecret{Secret: secretName, Namespace: namespace}
	} else if err != nil {
		return err
	}

	// Exract all keys from secret
	for name, value := range keySecret.Data {
		switch filepath.Ext(name) {
		case DecryptionPGPExt:
			if err = d.AddGPGKey(value); err != nil {
				return fmt.Errorf("failed to import data from %s decryption Secret '%s': %w", name, secretName, err)
			}
		case DecryptionAgeExt:
			if err = d.AddAgeKey(value); err != nil {
				return fmt.Errorf("failed to import data from %s decryption Secret '%s': %w", name, secretName, err)
			}
		case filepath.Ext(DecryptionVaultTokenFileName):
			// Make sure we have the absolute name
			if name == DecryptionVaultTokenFileName {
				token := string(value)
				token = strings.Trim(strings.TrimSpace(token), "\n")
				d.vaultToken = token
			}
		case filepath.Ext(DecryptionAWSKmsFile):
			if name == DecryptionAWSKmsFile {
				if d.awsCredsProvider, err = awskms.LoadCredsProviderFromYaml(value); err != nil {
					return fmt.Errorf("failed to import data from %s decryption Secret '%s': %w", name, secretName, err)
				}
			}
		case filepath.Ext(DecryptionAzureAuthFile):
			// Make sure we have the absolute name
			if name == DecryptionAzureAuthFile {
				conf := azkv.AADConfig{}
				if err = azkv.LoadAADConfigFromBytes(value, &conf); err != nil {
					return fmt.Errorf("failed to import data from %s decryption Secret '%s': %w", name, secretName, err)
				}
				if d.azureToken, err = azkv.TokenFromAADConfig(conf); err != nil {
					return fmt.Errorf("failed to import data from %s decryption Secret '%s': %w", name, secretName, err)
				}
			}
		case filepath.Ext(DecryptionGCPCredsFile):
			if name == DecryptionGCPCredsFile {
				d.gcpCredsJSON = bytes.Trim(value, "\n")
			}
		}
	}

	return nil
}

// Read reads the input data, decrypts it, and returns the decrypted data.
func (d *SOPSDecryptor) Decrypt(data []byte) (content map[string]interface{}, err error) {
	if !d.Config.SkipDecrypt {
		data, err = d.SopsDecryptWithFormat(data, formats.Json, formats.Json)
		if err != nil {
			return nil, err
		}
	}

	err = json.Unmarshal(data, &content)
	if err != nil {
		return nil, err
	}
	delete(content, "sops")

	return content, err
}

// SopsDecryptWithFormat attempts to load a SOPS encrypted file using the store
// for the input format, gathers the data key for it from the key service,
// and then decrypts the file data with the retrieved data key.
// It returns the decrypted bytes in the provided output format, or an error.
func (d *SOPSDecryptor) SopsDecryptWithFormat(data []byte, inputFormat, outputFormat formats.Format) (_ []byte, err error) {
	defer func() {
		// It was discovered that malicious input and/or output instructions can
		// make SOPS panic. Recover from this panic and return as an error.
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to emit encrypted %s file as decrypted %s: %v",
				sopsFormatToString[inputFormat], sopsFormatToString[outputFormat], r)
		}
	}()

	store := common.StoreForFormat(inputFormat)

	tree, err := store.LoadEncryptedFile(data)
	if err != nil {
		return nil, sopsUserErr(fmt.Sprintf("failed to load encrypted %s data", sopsFormatToString[inputFormat]), err)
	}

	for _, group := range tree.Metadata.KeyGroups {
		// Sort MasterKeys in the group so offline ones are tried first
		sort.SliceStable(group, func(i, j int) bool {
			return intkeyservice.IsOfflineMethod(group[i]) && !intkeyservice.IsOfflineMethod(group[j])
		})
	}

	metadataKey, err := tree.Metadata.GetDataKeyWithKeyServices(d.keyServiceServer())
	if err != nil {
		return nil, sopsUserErr("cannot get sops data key", err)
	}

	cipher := aes.NewCipher()
	mac, err := tree.Decrypt(metadataKey, cipher)
	if err != nil {
		return nil, sopsUserErr("error decrypting sops tree", err)
	}

	if d.checkSopsMac {
		// Compute the hash of the cleartext tree and compare it with
		// the one that was stored in the document. If they match,
		// integrity was preserved
		// Ref: go.mozilla.org/sops/v3/decrypt/decrypt.go
		originalMac, err := cipher.Decrypt(
			tree.Metadata.MessageAuthenticationCode,
			metadataKey,
			tree.Metadata.LastModified.Format(time.RFC3339),
		)
		if err != nil {
			return nil, sopsUserErr("failed to verify sops data integrity", err)
		}
		if originalMac != mac {
			// If the file has an empty MAC, display "no MAC"
			if originalMac == "" {
				originalMac = "no MAC"
			}
			return nil, fmt.Errorf("failed to verify sops data integrity: expected mac '%s', got '%s'", originalMac, mac)
		}
	}

	outputStore := common.StoreForFormat(outputFormat)
	out, err := outputStore.EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, sopsUserErr(fmt.Sprintf("failed to emit encrypted %s file as decrypted %s",
			sopsFormatToString[inputFormat], sopsFormatToString[outputFormat]), err)
	}
	return out, err
}

// keyServiceServer returns the SOPS (local) key service clients used to serve
// decryption requests. loadKeyServiceServers() is only configured on the first
// call.
func (d *SOPSDecryptor) keyServiceServer() []keyservice.KeyServiceClient {
	d.localServiceOnce.Do(func() {
		d.loadKeyServiceServers()
	})
	return d.keyServices
}

// loadKeyServiceServers loads the SOPS (local) key service clients used to
// serve decryption requests for the current set of Decryptor
// credentials.
func (d *SOPSDecryptor) loadKeyServiceServers() {
	serverOpts := []intkeyservice.ServerOption{
		intkeyservice.WithGnuPGHome(d.gnuPGHome),
		intkeyservice.WithVaultToken(d.vaultToken),
		intkeyservice.WithAgeIdentities(d.ageIdentities),
		intkeyservice.WithGCPCredsJSON(d.gcpCredsJSON),
	}
	if d.azureToken != nil {
		serverOpts = append(serverOpts, intkeyservice.WithAzureToken{Token: d.azureToken})
	}
	serverOpts = append(serverOpts, intkeyservice.WithAWSKeys{CredsProvider: d.awsCredsProvider})
	server := intkeyservice.NewServer(serverOpts...)
	d.keyServices = append(make([]keyservice.KeyServiceClient, 0), keyservice.NewCustomLocalClient(server))
}

func sopsUserErr(msg string, err error) error {
	if userErr, ok := err.(sops.UserError); ok {
		err = fmt.Errorf(userErr.UserError())
	}
	return fmt.Errorf("%s: %w", msg, err)
}

func detectFormatFromMarkerBytes(b []byte) formats.Format {
	for k, v := range sopsFormatToMarkerBytes {
		if bytes.Contains(b, v) {
			return k
		}
	}
	return unsupportedFormat
}

// keyServiceServer returns the SOPS (local) key service clients used to serve
// decryption requests. loadKeyServiceServers() is only configured on the first
// call.
// loadKeyServiceServers loads the SOPS (local) key service clients used to
// func (d *SOPSDecryptor) keyServiceServer() []keyservice.KeyServiceClient {
// 	d.localServiceOnce.Do(func() {
// 		d.loadKeyServiceServers()
// 	})
// 	return d.keyServices
// }

// // loadKeyServiceServers loads the SOPS (local) key service clients used to
// // serve decryption requests for the current set of Decryptor
// // credentials.
// func (d *SOPSDecryptor) loadKeyServiceServers() {
// 	serverOpts := []intkeyservice.ServerOption{
// 		intkeyservice.WithGnuPGHome(d.gnuPGHome),
// 		intkeyservice.WithVaultToken(d.vaultToken),
// 		intkeyservice.WithAgeIdentities(d.ageIdentities),
// 		intkeyservice.WithGCPCredsJSON(d.gcpCredsJSON),
// 	}
// 	if d.azureToken != nil {
// 		serverOpts = append(serverOpts, intkeyservice.WithAzureToken{Token: d.azureToken})
// 	}
// 	serverOpts = append(serverOpts, intkeyservice.WithAWSKeys{CredsProvider: d.awsCredsProvider})
// 	server := intkeyservice.NewServer(serverOpts...)
// 	d.keyServices = append(make([]keyservice.KeyServiceClient, 0), keyservice.NewCustomLocalClient(server))
// }

func gpgHome() string {
	dir := os.Getenv("GNUPGHOME")
	if dir == "" {
		usr, err := user.Current()
		if err != nil {
			return path.Join(os.Getenv("HOME"), "/.gnupg")
		}
		return path.Join(usr.HomeDir, ".gnupg")
	}
	return dir
}

func secRing() string {
	return fmt.Sprint(gpgHome() + "/secring.gpg")
}
