package decryptors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Generate KeyPair For Testing
//   $ ejson keygen
//   Public Key:
//   9474413baa1422b613beed7fd2ba8201d433758dc94aaee4d385d0c948176c4d
//   Private Key:
//   65b2f2060e6e3a976456c5a7cbcca3f15715eb1d9e0fe54174fa7b36aca1f50e

// Example data; this will need to be valid for your use case.
const mockPrivateKey = "65b2f2060e6e3a976456c5a7cbcca3f15715eb1d9e0fe54174fa7b36aca1f50e"

const EncryptedEjsonContent = `{
	"_public_key": "9474413baa1422b613beed7fd2ba8201d433758dc94aaee4d385d0c948176c4d",
	"data": {
	  "database_password": "EJ[1:CuPlhIlHfYXnHQZA4lcF5yIL2ELZp6qcbOfHEWoQegs=:ZPXRiyzY2sCSggghVuOFfM0vHzqY7hSf:BZyLg1crv4xkgGL1JyYRnt3pj3bttOUW2QIo]",
	  "database_user": "EJ[1:CuPlhIlHfYXnHQZA4lcF5yIL2ELZp6qcbOfHEWoQegs=:QrrHbddJpx/eP3t4sMNCT6OeZi7MPq0m:y+I+og1GqEas4r/4hV5vzbXpG9JA2elo45Ws]"
	}
}`
const DecryptedEjsonContent = `{
	"data": {
	  "database_password": "VERY_SECRET",
	  "database_user": "MUCH_SECURE"
	}
}`
const FaultyEjsonContent = `{
	"_public_key": "9474413baa1422b613beed7fd2ba8201d433758dc94aaee4d385d0c948176c4d",
	"data": {
	  "faulty"="json"
	}
}`

func testkeydirPath() string {
	hackDirPath := filepath.Join(testdataPath(), "ejson", "keydir")
	return hackDirPath
}

func TestAddKey(t *testing.T) {
	decryptor, err := NewEJSONDecryptor(DecryptorConfig{}, "")
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}
	err = decryptor.AddKey(mockPrivateKey)

	assert.NoError(t, err, "Expected no error when adding a private key")
	assert.Contains(t, decryptor.keys, mockPrivateKey, "Expected the key to be added to the keys slice")
}

func TestMultipleKeyFromDiskAddition(t *testing.T) {
	decryptor, err := NewEJSONDecryptor(DecryptorConfig{}, testkeydirPath())
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}

	files, _ := os.ReadDir(testkeydirPath())
	for _, file := range files {
		if !file.IsDir() {
			content, err := os.ReadFile(filepath.Join(testkeydirPath(), file.Name()))
			if err != nil {
				t.Fatalf("Failed to read file: %v", err)
			}
			keyContent := string(content)
			assert.Contains(t, decryptor.keys, keyContent, "Expected the key to be added to the keys slice")
		}
	}
}

func TestMultipleKeyAddition(t *testing.T) {
	var keysFromFile []string
	decryptor, err := NewEJSONDecryptor(DecryptorConfig{}, testkeydirPath())
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}

	files, _ := os.ReadDir(testkeydirPath())
	for _, file := range files {
		if !file.IsDir() {
			content, err := os.ReadFile(filepath.Join(testkeydirPath(), file.Name()))
			if err != nil {
				t.Fatalf("Failed to read file: %v", err)
			}
			keyContent := string(content)
			keysFromFile = append(keysFromFile, keyContent)
			decryptor.AddKey(keyContent)
		}
	}

	// Test at the end if all keys are added
	for _, key := range keysFromFile {
		assert.Contains(t, decryptor.keys, key, "Expected the key to be added to the keys slice")
	}
}

func TestAddFaultyKey(t *testing.T) {
	faultyKey := "65b2f2060e6e3a9764b1d9e0fe54174fa7b36aca1f50e"
	decryptor, err := NewEJSONDecryptor(DecryptorConfig{}, "")
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}
	err = decryptor.AddKey(faultyKey)

	assert.Error(t, err, "Expected error when adding a faulty private key")
	assert.NotContains(t, decryptor.keys, faultyKey, "Did not expect the key to be added to the keys slice")
}

func TestIsEncrypted(t *testing.T) {
	decryptor, err := NewEJSONDecryptor(DecryptorConfig{}, "")
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}
	isEncrypted, err := decryptor.IsEncrypted([]byte(EncryptedEjsonContent))

	assert.NoError(t, err, "Expected no error when checking if content is encrypted")
	assert.True(t, isEncrypted, "Expected the content to be identified as encrypted")
}

func TestDecrypt(t *testing.T) {
	decryptor, err := NewEJSONDecryptor(DecryptorConfig{SkipDecrypt: false}, "")
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}
	_ = decryptor.AddKey(mockPrivateKey) // Assuming the key is valid and is added without errors.

	decryptedContent, err := decryptor.Decrypt([]byte(EncryptedEjsonContent))

	assert.NoError(t, err, "Expected no error during decryption")
	assert.NotNil(t, decryptedContent, "Expected decrypted content to be non-nil")

	// Convert expected JSON content to map
	var expectedMap map[string]interface{}
	err = json.Unmarshal([]byte(DecryptedEjsonContent), &expectedMap)
	assert.NoError(t, err, "Failed to unmarshal test data expected content")

	// Compare the decrypted content with the expected value
	assert.Equal(t, expectedMap, decryptedContent, "The decrypted content does not match the expected value.")
}
