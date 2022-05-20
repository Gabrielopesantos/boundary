package workerauth

import (
	"context"
	"crypto/x509"
	"database/sql"
	"fmt"
	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"strconv"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/types/scope"
	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/protobuf/proto"
)

// Ensure we implement the Storage interfaces
var (
	_ nodee.Storage              = (*RepositoryStorage)(nil)
	_ nodee.TransactionalStorage = (*RepositoryStorage)(nil)
)

// RepositoryStorage is the Worker Auth database repository
type RepositoryStorage struct {
	reader db.Reader
	writer db.Writer
	kms    *kms.Kms

	defaultLimit int
}

// NewRepository creates a new Worker Auth RepositoryStorage that implements the Storage interface,
// Supports the options: WithLimit which sets a default limit on results returned by repo operations.
func NewRepository(r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*RepositoryStorage, error) {
	const op = "workerauth.NewRepository"
	if r == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil reader")
	}
	if w == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil writer")
	}
	if kms == nil {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "nil kms")
	}
	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = db.DefaultLimit
	}
	return &RepositoryStorage{
		reader:       r,
		writer:       w,
		kms:          kms,
		defaultLimit: opts.withLimit,
	}, nil
}

// Flush is called when storage is done being performed. The boolean parameter
// indicates whether the operation was successful (true) or failed (false).
func (r *RepositoryStorage) Flush(b bool) error {
	if b == false {
		return fmt.Errorf("Worker Auth Repository operation failed.")
	}
	return nil
}

// Store stores the message
func (r *RepositoryStorage) Store(ctx context.Context, msg nodee.MessageWithId) error {
	const op = "workerauth.(RepositoryStorage).Store"
	if err := types.ValidateMessage(msg); err != nil {
		return fmt.Errorf("(%s) given message cannot be stored: %w", op, err)
	}
	if msg.GetId() == "" {
		return fmt.Errorf("(%s) given message cannot be stored as it has no ID.", op)
	}
	// Determine type of message to store
	marshaledBytes, err := proto.Marshal(msg.(proto.Message))
	if err != nil {
		return fmt.Errorf("error marshaling nodee.MessageWithId: %w", err)
	}
	switch msg.(type) {
	case *types.NodeInformation:
		node, err := unmarshalNodeInformation(ctx, marshaledBytes)
		if err != nil {
			return err
		}
		err = r.storeNodeCertificate(ctx, node)
	case *types.RootCertificate:
		cert, err := unmarshalRootCertificate(ctx, marshaledBytes)
		if err != nil {
			return err
		}
		err = r.storeRootCertificate(ctx, cert)
	default:
		err = fmt.Errorf("(%s) Message type not supported for Store", op)
	}
	if err != nil {
		r.Flush(false)
		return errors.Wrap(ctx, err, op)
	}
	r.Flush(true)
	return nil
}

func (r *RepositoryStorage) storeNodeCertificate(ctx context.Context, node *types.NodeInformation) error {
	const op = "workerauth.(RepositoryStorage).storeNodeCertificate"

	nodeAuth := servers.AllocWorkerAuth()
	nodeAuth.WorkerKeyIdentifier = node.Id
	nodeAuth.WorkerEncryptionPubKey = node.EncryptionPublicKeyBytes
	nodeAuth.WorkerSigningPubKey = node.CertificatePublicKeyPkix
	nodeAuth.Nonce = node.RegistrationNonce

	// Encrypt the private key
	databaseWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	nodeAuth.KeyId, err = databaseWrapper.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	nodeAuth.ControllerEncryptionPrivKey, err = encrypt(ctx, node.ServerEncryptionPrivateKeyBytes, databaseWrapper)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// workerId is passed in the context of the AuthorizeNode call
	workerId := ctx.Value("workerId")
	if workerId == nil {
		return errors.Wrap(ctx, fmt.Errorf("Worker NodeInformation cannot be stored as no workerId was passed in"), op)
	}

	nodeAuth.WorkerId = workerId.(string)

	err = nodeAuth.ValidateNewWorkerAuth(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			// Store WorkerAuth
			onConflict := &db.OnConflict{
				Target: db.Constraint("worker_auth_authorized_pkey"),
				Action: db.SetColumns([]string{"controller_encryption_priv_key"}),
			}
			if err := r.writer.Create(ctx, &nodeAuth, db.WithOnConflict(onConflict)); err != nil {
				return errors.Wrap(ctx, err, op)
			}

			// Then store cert bundles associated with this WorkerAuth
			for _, c := range node.CertificateBundles {
				err := r.storeWorkerCertBundle(ctx, c, nodeAuth.WorkerKeyIdentifier)
				if err != nil {
					return errors.Wrap(ctx, err, op)
				}
			}

			return nil
		},
	)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (r *RepositoryStorage) storeWorkerCertBundle(ctx context.Context, bundle *types.CertificateBundle, workerKeyIdentifier string) error {
	const op = "workerauth.(RepositoryStorage).storeWorkerCertBundle"

	workerCertBundle := servers.AllocWorkerCertBundle()
	bundleBytes, err := proto.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("error marshaling nodetypes.CertificateBundle: %w", err)
	}

	// Extract serial number from CA cert
	caCert := bundle.CaCertificateDer
	parsedCert, err := x509.ParseCertificate(caCert)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	workerCertBundle.CertificatePublicKey = parsedCert.AuthorityKeyId
	workerCertBundle.CertBundle = bundleBytes
	workerCertBundle.WorkerKeyIdentifier = workerKeyIdentifier

	err = workerCertBundle.ValidateNewWorkerCertBundle(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if err := r.writer.Create(ctx, &workerCertBundle); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func (r *RepositoryStorage) storeRootCertificate(ctx context.Context, cert *types.RootCertificate) error {
	const op = "workerauth.(RepositoryStorage).storeRootCertificate"

	rootCert := servers.AllocRootCertificate()

	parsedCert, err := x509.ParseCertificate(cert.CertificateDer)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	rootCert.SerialNumber = parsedCert.SerialNumber.Uint64()
	rootCert.Certificate = cert.CertificateDer
	rootCert.NotValidAfter = timestamp.New(cert.NotAfter.AsTime())
	rootCert.NotValidBefore = timestamp.New(cert.NotBefore.AsTime())
	rootCert.PublicKey = cert.PublicKeyPkix
	rootCert.State = cert.Id

	// Encrypt the private key
	databaseWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	rootCert.KeyId, err = databaseWrapper.KeyId(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	rootCert.PrivateKey, err = encrypt(ctx, cert.PrivateKeyPkcs8, databaseWrapper)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	err = rootCert.ValidateNewRootCertificate(ctx)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	_, err = r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			// Delete the old cert with this id first- there can only ever be one next or current at a time
			r.removeRootCertificate(ctx, cert.Id)

			// Then insert the new cert
			if err = r.writer.Create(ctx, &rootCert); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// Load loads values into the given message. The message must be populated
// with the ID value. If not found, the returned error should be ErrNotFound.
func (r *RepositoryStorage) Load(ctx context.Context, msg nodee.MessageWithId) error {
	const op = "workerauth.(RepositoryStorage).Load"
	if err := types.ValidateMessage(msg); err != nil {
		return fmt.Errorf("(%s) given message cannot be loaded: %w", op, err)
	}
	if msg.GetId() == "" {
		return fmt.Errorf("(%s) given message cannot be stored as it has no ID.", op)
	}

	marshaledBytes, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("error marshaling nodee.MessageWithId: %w", err)
	}
	switch msg.(type) {
	case *types.NodeInformation:
		node, err := unmarshalNodeInformation(ctx, marshaledBytes)
		if err != nil {
			return err
		}
		err = r.loadNodeCertificate(ctx, node, msg)
	case *types.RootCertificate:
		cert, err := unmarshalRootCertificate(ctx, marshaledBytes)
		if err != nil {
			return err
		}
		err = r.loadRootCertificate(ctx, cert, msg)
	default:
		err = fmt.Errorf("(%s) Message type not supported for Load", op)
	}
	if err != nil {
		r.Flush(false)
		return errors.Wrap(ctx, err, op)
	}
	r.Flush(true)
	return nil
}

func (r *RepositoryStorage) loadNodeCertificate(ctx context.Context, node *types.NodeInformation, result proto.Message) error {
	const op = "workerauth.(RepositoryStorage).loadNodeCertificate"

	authorizedWorker, err := r.findWorkerAuth(ctx, node)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if authorizedWorker == nil {
		node.Authorized = false
		return nodee.ErrNotFound
	}

	node.EncryptionPublicKeyBytes = authorizedWorker.WorkerEncryptionPubKey
	node.CertificatePublicKeyPkix = authorizedWorker.WorkerSigningPubKey
	node.RegistrationNonce = authorizedWorker.Nonce

	// Default values are used for key types
	node.EncryptionPublicKeyType = types.KEYTYPE_KEYTYPE_X25519
	node.CertificatePublicKeyType = types.KEYTYPE_KEYTYPE_ED25519
	node.ServerEncryptionPrivateKeyType = types.KEYTYPE_KEYTYPE_X25519

	// decrypt private key
	databaseWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase, kms.WithKeyId(authorizedWorker.KeyId))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	node.ServerEncryptionPrivateKeyBytes, err = decrypt(ctx, authorizedWorker.ControllerEncryptionPrivKey, databaseWrapper)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	// Get cert bundles from the other table
	certBundles, err := r.findCertBundles(ctx, node.Id)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	node.CertificateBundles = certBundles

	node.Authorized = true

	return unmarshalNodeToResult(ctx, node, result)
}

func (r *RepositoryStorage) findCertBundles(ctx context.Context, workerKeyId string) ([]*types.CertificateBundle, error) {
	const op = "workerauth.(RepositoryStorage).findCertBundles"

	where := fmt.Sprintf("worker_key_identifier= '%s'", workerKeyId)
	var bundles []*servers.WorkerCertBundle
	if err := r.reader.SearchWhere(
		ctx,
		&bundles,
		where,
		[]interface{}{},
		db.WithLimit(-1),
	); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	certBundle := []*types.CertificateBundle{}
	for _, bundle := range bundles {
		thisBundle := &types.CertificateBundle{}
		if err := proto.Unmarshal(bundle.WorkerCertBundle.CertBundle, thisBundle); err != nil {
			return nil, errors.New(ctx, errors.Decode, op, "error unmarshaling message", errors.WithWrap(err))
		}
		certBundle = append(certBundle, thisBundle)
	}

	return certBundle, nil
}

func (r *RepositoryStorage) findWorkerAuth(ctx context.Context, node *types.NodeInformation) (*servers.WorkerAuth, error) {
	const op = "workerauth.(RepositoryStorage).findWorkerAuth"

	worker := servers.AllocWorkerAuth()
	worker.WorkerKeyIdentifier = node.Id
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			if err := read.LookupById(ctx, worker); err != nil {
				return err
			}
			return nil
		},
	)
	if err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op)
	}

	return worker, nil
}

func (r *RepositoryStorage) loadRootCertificate(ctx context.Context, cert *types.RootCertificate, result proto.Message) error {
	const op = "workerauth.(RepositoryStorage).loadRootCertificate"

	rootCertificate := servers.AllocRootCertificate()
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			if err := r.reader.SearchWhere(
				ctx,
				&rootCertificate,
				"state = ?",
				[]interface{}{cert.Id},
				db.WithLimit(-1),
			); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	if rootCertificate.Certificate == nil {
		return nodee.ErrNotFound
	}

	cert.CertificateDer = rootCertificate.Certificate
	cert.NotAfter = rootCertificate.NotValidAfter.Timestamp
	cert.NotBefore = rootCertificate.NotValidBefore.Timestamp
	cert.PublicKeyPkix = rootCertificate.PublicKey
	cert.PrivateKeyType = types.KEYTYPE_KEYTYPE_ED25519

	// decrypt private key
	databaseWrapper, err := r.kms.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeDatabase, kms.WithKeyId(rootCertificate.KeyId))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	cert.PrivateKeyPkcs8, err = decrypt(ctx, rootCertificate.PrivateKey, databaseWrapper)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	certBytes, err := proto.Marshal(cert)
	if err != nil {
		return errors.New(ctx, errors.Decode, op, "error marshaling RootCertificate", errors.WithWrap(err))
	}
	if err := proto.Unmarshal(certBytes, result); err != nil {
		return errors.New(ctx, errors.Decode, op, "error unmarshaling message", errors.WithWrap(err))
	}

	return nil
}

// Remove removes the given message. Only the ID field of the message is considered.
func (r *RepositoryStorage) Remove(ctx context.Context, msg nodee.MessageWithId) error {
	const op = "workerauth.(RepositoryStorage).Remove"
	if err := types.ValidateMessage(msg); err != nil {
		return fmt.Errorf("(%s) given message cannot be removed: %w", op, err)
	}
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			var err error
			// Determine type of message to remove
			switch msg.(type) {
			case *types.NodeInformation:
				err = r.removeNodeCertificate(ctx, msg.GetId())
			case *types.RootCertificate:
				err = r.removeRootCertificate(ctx, msg.GetId())
			default:
				err = fmt.Errorf("(%s) Message type not supported for Remove", op)
			}
			return err
		},
	)
	if err != nil {
		r.Flush(false)
		return errors.Wrap(ctx, err, op)
	}
	r.Flush(true)
	return nil
}

func (r *RepositoryStorage) removeNodeCertificate(ctx context.Context, id string) error {
	const op = "workerauth.(RepositoryStorage).removeNodeCertificate"

	rows, err := r.writer.Exec(ctx, deleteNodeInformationQuery, []interface{}{
		sql.Named("worker_key_identifier", id),
	})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete node certificate"))
	}
	if rows > 1 {
		return errors.New(ctx, errors.MultipleRecords, op, "more than 1 node certificate would have been deleted")
	}

	return nil
}

func (r *RepositoryStorage) removeRootCertificate(ctx context.Context, id string) error {
	const op = "workerauth.(RepositoryStorage).removeRootCertificate"

	rows, err := r.writer.Exec(ctx, deleteRootCertificateQuery, []interface{}{
		sql.Named("state", id),
	})
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete root certificate"))
	}
	if rows > 1 {
		return errors.New(ctx, errors.MultipleRecords, op, "more than 1 root certificate would have been deleted")
	}

	return nil
}

// List returns a list of IDs; the type of the message is used to disambiguate what to list.
func (r *RepositoryStorage) List(ctx context.Context, msg proto.Message) ([]string, error) {
	const op = "workerauth.(RepositoryStorage).List"

	var err error
	var ids []string
	// Determine type of message to store
	switch msg.(type) {
	case *types.NodeInformation:
		ids, err = r.listNodeInformation(ctx)
	case *types.RootCertificate:
		ids, err = r.listRootCertificates(ctx)
	default:
		ids, err = nil, fmt.Errorf("(%s) Message type not supported for List", op)
	}
	if err != nil {
		r.Flush(false)
		return nil, errors.Wrap(ctx, err, op)
	}
	r.Flush(true)
	return ids, nil
}

// Returns a list of node auth IDs
func (r *RepositoryStorage) listNodeInformation(ctx context.Context) ([]string, error) {
	const op = "workerauth.(RepositoryStorage).listNodeCertificates"

	var where string
	var nodeAuths []*servers.WorkerAuth
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			if err := r.reader.SearchWhere(
				ctx,
				&nodeAuths,
				where,
				[]interface{}{},
				db.WithLimit(-1),
			); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var nodeIds []string
	for _, auth := range nodeAuths {
		nodeIds = append(nodeIds, auth.WorkerKeyIdentifier)
	}
	return nodeIds, nil
}

// Returns a list of root certificate serial numbers
func (r *RepositoryStorage) listRootCertificates(ctx context.Context) ([]string, error) {
	const op = "workerauth.(RepositoryStorage).listRootCertificates"

	var where string
	var rootCertificates []*servers.RootCertificate
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			if err := r.reader.SearchWhere(
				ctx,
				&rootCertificates,
				where,
				[]interface{}{},
				db.WithLimit(-1),
			); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			return nil
		},
	)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var certIds []string
	for _, cert := range rootCertificates {
		certIds = append(certIds, strconv.FormatUint(cert.SerialNumber, 10))
	}
	return certIds, nil
}

// encrypt value before writing it to the db
func encrypt(ctx context.Context, value []byte, wrapper wrapping.Wrapper) ([]byte, error) {
	blobInfo, err := wrapper.Encrypt(ctx, value)
	if err != nil {
		return nil, fmt.Errorf("error encrypting recovery info: %w", err)
	}
	marshaledBlob, err := proto.Marshal(blobInfo)
	if err != nil {
		return nil, fmt.Errorf("error marshaling encrypted blob: %w", err)
	}
	return marshaledBlob, nil
}

func decrypt(ctx context.Context, value []byte, wrapper wrapping.Wrapper) ([]byte, error) {
	blobInfo := new(wrapping.BlobInfo)
	if err := proto.Unmarshal(value, blobInfo); err != nil {
		return nil, fmt.Errorf("error decoding encrypted blob: %w", err)
	}

	marshaledInfo, err := wrapper.Decrypt(ctx, blobInfo)
	if err != nil {
		return nil, fmt.Errorf("error decrypting recovery info: %w", err)
	}

	return marshaledInfo, nil
}

func unmarshalNodeInformation(ctx context.Context, marshaledBytes []byte) (*types.NodeInformation, error) {
	const op = "auth.(RepositoryStorage).unmarshalNodeInformation"
	node := &types.NodeInformation{}
	if err := proto.Unmarshal(marshaledBytes, node); err != nil {
		return nil, errors.New(ctx, errors.Decode, op, "error unmarshaling message", errors.WithWrap(err))
	}
	return node, nil
}

func unmarshalRootCertificate(ctx context.Context, marshaledBytes []byte) (*types.RootCertificate, error) {
	const op = "auth.(RepositoryStorage).unmarshalRootCertificate"
	cert := &types.RootCertificate{}
	if err := proto.Unmarshal(marshaledBytes, cert); err != nil {
		return nil, errors.New(ctx, errors.Decode, op, "error unmarshaling message", errors.WithWrap(err))
	}
	return cert, nil
}

func unmarshalNodeToResult(ctx context.Context, node *types.NodeInformation, result proto.Message) error {
	const op = "auth.(RepositoryStorage).unmarshalNodeToResult"
	nodeBytes, err := proto.Marshal(node)
	if err != nil {
		return fmt.Errorf("error marshaling nodetypes.NodeInformation: %w", err)
	}
	if err := proto.Unmarshal(nodeBytes, result); err != nil {
		return errors.New(ctx, errors.Decode, op, "error unmarshalling message", errors.WithWrap(err))
	}
	return nil
}
