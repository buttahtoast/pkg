package sops

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/buttahtoast/pkg/decryptors"
	"github.com/stretchr/testify/assert"
)

func testdataPath() string {
	basePath, _ := os.Getwd()
	hackDirPath := filepath.Join(basePath, "decryptors", "ejson", "testdata")
	return hackDirPath
}

func TestSOPSIsEncrypted(t *testing.T) {
	d, _ := os.ReadFile(filepath.Join(testdataPath(), "sops", "secret-pgp.yaml"))

	decryptor := NewSOPSDecryptor(decryptors.DecryptorConfig{}, "")
	isEncrypted, err := decryptor.IsEncrypted(d)

	assert.NoError(t, err, "Expected no error when checking if content is encrypted")
	assert.True(t, isEncrypted, "Expected the content to be identified as encrypted")
}

func TestSOPSIsNotEncrypted(t *testing.T) {
	d, _ := os.ReadFile(filepath.Join(testdataPath(), "sops", "secret.yaml"))

	decryptor := NewSOPSDecryptor(decryptors.DecryptorConfig{}, "")
	isEncrypted, err := decryptor.IsEncrypted(d)

	assert.NoError(t, err, "Expected no error when checking if content is encrypted")
	assert.False(t, isEncrypted, "Expected the content to be identified as not encrypted")
}

func TestSOPSGPGEncryption(t *testing.T) {
	private, _ := os.ReadFile(filepath.Join(testdataPath(), "sops", "pgp.asc"))
	d, _ := os.ReadFile(filepath.Join(testdataPath(), "sops", "secret-pgp.yaml"))

	decryptor, cleanup, err := NewSOPSTempDecryptor(decryptors.DecryptorConfig{})
	assert.NoError(t, err, "Expected no error when initializing decryptor")
	defer cleanup()

	err = decryptor.AddGPGKey([]byte(private))
	assert.NoError(t, err, "Expected no error when adding GPG Key")

	enc, err := decryptor.Decrypt(d)
	assert.NoError(t, err, "Expected no error when decrypting content")

	sData := enc["stringData"].(map[string]interface{})
	assert.Equal(t, "VERY_SECRET", sData["database_password"], "Expected the database_password to be decrypted")
	assert.Equal(t, "MUCH_SECURE", sData["database_user"], "Expected the database_user to be decrypted")
}

func TestSOPSAgeEncryption(t *testing.T) {
	private, _ := os.ReadFile(filepath.Join(testdataPath(), "sops", "age.agekey"))
	d, _ := os.ReadFile(filepath.Join(testdataPath(), "sops", "secret-age.yaml"))

	decryptor, cleanup, err := NewSOPSTempDecryptor(decryptors.DecryptorConfig{})
	assert.NoError(t, err, "Expected no error when initializing decryptor")
	defer cleanup()

	err = decryptor.AddAgeKey([]byte(private))
	assert.NoError(t, err, "Expected no error when adding Age Key")

	enc, err := decryptor.Decrypt(d)
	assert.NoError(t, err, "Expected no error when decrypting content")

	sData := enc["stringData"].(map[string]interface{})
	assert.Equal(t, "VERY_SECRET", sData["database_password"], "Expected the database_password to be decrypted")
	assert.Equal(t, "MUCH_SECURE", sData["database_user"], "Expected the database_user to be decrypted")
}
