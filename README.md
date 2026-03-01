# Malzahar

A secure Windows command-line transfer client.

## Features

- RSA OAEP + HMAC signed request flow
- `pull` downloads encrypted zip content, extracts it, and updates the target folder
- `push` zips a local folder, encrypts it with AES-GCM, and uploads it
- `connect/check/pull/push/manage` command set
- `paths.ini` mapping for `resource -> local path`

## Requirements

- Windows x64
- CMake + MSVC toolchain
- OpenSSL (via vcpkg)
- PowerShell (`Compress-Archive` / `Expand-Archive`)

## Build (example)

```powershell
cmake --preset x64-release --fresh
cmake --build --preset x64-release
```

Note: Building with a static triplet reduces runtime dependencies.

## Secrets

Secrets are loaded from the working directory instead of being hardcoded:

- `hmac.key` -> must match server `private.api.hmac-key`
- `private_key.pem` -> RSA private key (PEM format, including BEGIN/END lines)

If these files are missing, the app exits at startup.

## Before Pushing To GitHub

Do not commit `hmac.key` and `private_key.pem`.

Example `.gitignore`:

```gitignore
hmac.key
private_key.pem
```

## Commands

```text
login <name>,<password>
connect <Public|Private>,<folder>,<path>
check <Public|Private>,<folder>
pull <Public|Private>,<folder>[,<version>]
push <Public|Private>,<folder>
manage <Public|Private>,<folder>,<version>
```

## `paths.ini` Behavior

If `connect` succeeds, `paths.ini` is created/updated in the current working directory.

Line format:

```text
Public,NFSU2-C:\Example\Target\Folder
```

`check/pull/push/manage` validate this mapping before making server calls.

## Server Response Codes

- `0`: success (`check` may return `0|json`)
- `1`: signature/HMAC or payload format error
- `2`: RSA decrypt / JSON parse / generic format error
- `3`: user not found
- `4`: invalid password
- `5`: resource/version not found
- `6`: permission denied

## Quick Flow

1. `login`
2. `connect Public,NFSU2,C:\Target`
3. `check Public,NFSU2`
4. `pull Public,NFSU2`
5. After local changes, `push Public,NFSU2`
6. If needed, `manage Public,NFSU2,<version>`

## Notes

- Application icon is embedded into the EXE using `Malzahar.png` -> `Malzahar.ico`.
- `pull` clears target directory contents before applying the extracted zip content.
- `push` generates a new AES key for every operation.
****
