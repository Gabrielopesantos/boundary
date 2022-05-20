package workerauth

const (
	deleteNodeInformationQuery = `
		delete from worker_auth_authorized
 		where worker_key_identifier = @worker_key_identifier;
	`

	deleteRootCertificateQuery = `
		delete from worker_auth_ca_certificate
 		where state = @state;
	`
)
