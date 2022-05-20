package workerauth

import (
	"context"
	"crypto/rand"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/types/known/timestamppb"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreRootCertificates(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsCache := kms.TestKms(t, conn, wrapper)
	// Ensures the global scope contains a valid root key
	err := kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader))
	require.NoError(err)
	wrapper, err = kmsCache.GetWrapper(context.Background(), scope.Global.String(), kms.KeyPurposeDatabase)
	require.NoError(err)
	require.NotNil(wrapper)

	rw := db.New(conn)
	workerAuthRepo, err := NewRepository(rw, rw, kmsCache)
	require.NoError(err)

	// Rotate will generate and store next and current, as we have none
	roots, err := rotation.RotateRootCertificates(ctx, workerAuthRepo)
	require.NoError(err)
	rootIds, err := workerAuthRepo.List(ctx, (*types.RootCertificate)(nil))
	require.NoError(err)
	assert.Len(rootIds, 2)

	// Read the next cert and validate the stored values are valid after encrypt and decrypt
	nextCert := &types.RootCertificate{Id: "next"}
	err = workerAuthRepo.Load(ctx, nextCert)
	require.NoError(err)
	assert.Equal(roots.Next.PrivateKeyPkcs8, nextCert.PrivateKeyPkcs8)

	// Red the current cert and validate the stored values are valid after encrypt and decrypt
	currentCert := &types.RootCertificate{Id: "current"}
	err = workerAuthRepo.Load(ctx, currentCert)
	require.NoError(err)
	assert.Equal(roots.Current.PrivateKeyPkcs8, currentCert.PrivateKeyPkcs8)

	// Remove next
	require.NoError(workerAuthRepo.Remove(ctx, &types.RootCertificate{Id: "next"}))
	rootIds, err = workerAuthRepo.List(ctx, (*types.RootCertificate)(nil))
	require.NoError(err)
	assert.Len(rootIds, 1)

	// Rotate again; next should be regenerated
	_, err = rotation.RotateRootCertificates(ctx, workerAuthRepo)
	require.NoError(err)
	rootIds, err = workerAuthRepo.List(ctx, (*types.RootCertificate)(nil))
	require.NoError(err)
	assert.Len(rootIds, 2)
}

func TestStoreWorkerAuth(t *testing.T) {
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	kmsCache := kms.TestKms(t, conn, wrapper)

	// Ensures the global scope contains a valid root key
	err := kmsCache.CreateKeys(context.Background(), scope.Global.String(), kms.WithRandomReader(rand.Reader))
	require.NoError(err)
	wrapper, err = kmsCache.GetWrapper(context.Background(), scope.Global.String(), kms.KeyPurposeDatabase)
	require.NoError(err)
	require.NotNil(wrapper)

	rw := db.New(conn)
	storage, err := NewRepository(rw, rw, kmsCache)
	require.NoError(err)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(err)

	worker := servers.TestWorker(t, conn, wrapper)

	// This happens on the worker
	fileStorage, err := file.NewFileStorage(ctx)
	require.NoError(err)
	nodeCreds, err := types.NewNodeCredentials(ctx, fileStorage)
	require.NoError(err)
	keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
	require.NoError(err)
	nodePubKey, err := curve25519.X25519(nodeCreds.EncryptionPrivateKeyBytes, curve25519.Basepoint)
	require.NoError(err)

	// Add in node information to storage so we have a key to use
	nodeInfo := &types.NodeInformation{
		Id:                       keyId,
		CertificatePublicKeyPkix: nodeCreds.CertificatePublicKeyPkix,
		CertificatePublicKeyType: nodeCreds.CertificatePrivateKeyType,
		EncryptionPublicKeyBytes: nodePubKey,
		EncryptionPublicKeyType:  nodeCreds.EncryptionPrivateKeyType,
		RegistrationNonce:        nodeCreds.RegistrationNonce,
		FirstSeen:                timestamppb.Now(),
	}
	registrationCache := new(nodeenrollment.TestCache)
	registrationCache.Set(nodeInfo.Id, nodeInfo)

	// The AuthorizeNode request will result in a WorkerAuth record being stored
	ctx = context.WithValue(ctx, "workerId", worker.PublicId)
	require.NoError(registration.AuthorizeNode(ctx, storage, keyId, nodeenrollment.WithRegistrationCache(registrationCache)))

	// We should now look for a node information value in storage and validate that it's populated
	nodeInfos, err := storage.List(ctx, (*types.NodeInformation)(nil))
	require.NoError(err)
	require.NotEmpty(nodeInfos)
	assert.Len(nodeInfos, 1)

	// Validate the stored fields match those from the worker
	nodeLookup := &types.NodeInformation{
		Id: keyId,
	}
	err = storage.Load(ctx, nodeLookup)
	require.NoError(err)
	assert.NotEmpty(nodeLookup)
	assert.Equal(nodeInfo.EncryptionPublicKeyBytes, nodeLookup.EncryptionPublicKeyBytes)
	assert.Equal(nodeInfo.RegistrationNonce, nodeLookup.RegistrationNonce)
	assert.Equal(nodeInfo.CertificatePublicKeyPkix, nodeLookup.CertificatePublicKeyPkix)
}
