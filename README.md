# enconfig

A Go package for managing encrypted configuration files, providing both a CLI tool and a library interface for secure configuration management.

## Installation

```bash
go install github.com/jpatters/enconfig/cmd/enconfig@latest
```

## CLI Usage

### Create a new configuration

```bash
enconfig create -e production
```

This creates:
- A new encryption key in `production.key`
- An empty encrypted configuration file at `production.yaml.enc`

### Edit configuration

```bash
enconfig edit -e production
```

Opens the decrypted configuration in your default editor ($EDITOR, defaults to vi).
Automatically re-encrypts and saves when you close the editor.

## Library Usage

```go
import "github.com/jpatters/enconfig"
```

### Basic Operations

```go
fSystem := os.DirFS(pathToCredentials)
enconfig.SetFS(fSystem)
enconfig.SetEnvironment("production")

val := enconfig.MustGetCredential("path.to.credential")
```

### Production Usage

Set `ENCONFIG_KEY` to the key for your production environment.

## File Structure

- `<environment>.key` - Encryption key file
- `<environment>.yaml.enc` - Encrypted configuration file

## Security Features

- AES-256-GCM encryption
- Secure key storage
- Clean removal of temporary files
- Separate storage of keys and encrypted data

## License

MIT
