// Package qmanage provides production implementations of qconn.CredentialStore
// and qdef.AuthorizationManager for secure client credential storage and
// server-side authorization management.
//
// # Client Storage
//
// The ClientStore implementation stores credentials in the system registry on Windows
// (HKLM\SOFTWARE\<appName>\client) and in /var/lib/<appName>/client/ on Unix systems.
//
// On Windows, private keys and provision tokens are encrypted using DPAPI before
// storage in the registry. On Unix systems, private keys are stored in files with
// mode 0600 (owner read/write only).
//
// # Server Storage
//
// The AuthManager implementation uses bbolt for persistent storage of client records,
// role definitions, and authorization mappings. On Windows it stores data in
// %PROGRAMDATA%\<appName>\server\, and on Unix in /var/lib/<appName>/server/.
//
// # Security Considerations
//
// Server-side CA and server private keys are stored unencrypted in the bbolt database.
// Encryption at rest for server storage is the caller's responsibility. Consider:
//
//   - Using filesystem-level encryption (dm-crypt, BitLocker, FileVault)
//   - Running the server in a secure enclave or HSM-backed environment
//   - Restricting file permissions on the data directory
//
// The appName parameter is validated to prevent path traversal attacks and must
// contain only alphanumeric characters, hyphens, and underscores.
package qmanage
