# SenseSpace DID Token Verification

A Python library for verifying JWT tokens with Ed25519 signatures using SS58 addresses.

## Installation

```bash
pip install sensespace-did
```

## Usage

### Basic Usage

```python
from sensespace_did import verify_token

# Your JWT token
token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9..."

# Verify the token
result = verify_token(token)

if result["success"]:
    print("Token verified successfully!")
    print(f"Subject: {result['subject']}")
    print(f"Claims: {result['claims']}")
else:
    print(f"Verification failed: {result.get('error')}")
```

### With DID Document Fetching

```python
from sensespace_did import verify_token

# Verify token and fetch DID document
result = verify_token(
    token=token,
    fetch_did=True,  # Enable DID document fetching
    did_base_url="https://api.sensespace.xyz/api/did/"  # Optional, this is the default
)

if result["success"]:
    print(f"Token verified: {result['claims']}")
    
    if result.get("did_fetch_success"):
        print(f"DID Document: {result['did_document']}")
```

### Custom DID URL

```python
# Use a custom DID service URL
result = verify_token(
    token=token,
    fetch_did=True,
    did_base_url="https://your-custom-did-service.com/api/did/"
)
```

## API Reference

### `verify_token(token, fetch_did=False, did_base_url="https://api.sensespace.xyz/api/did/")`

Verifies a JWT token with Ed25519 signature using SS58 address.

**Parameters:**
- `token` (str): The JWT token to verify
- `fetch_did` (bool, optional): Whether to fetch the DID document. Default: `False`
- `did_base_url` (str, optional): Base URL for DID API. Default: `"https://api.sensespace.xyz/api/did/"`

**Returns:**
A dictionary containing:
- `success` (bool): Whether verification succeeded
- `header` (dict): JWT header
- `payload` (dict): JWT payload
- `claims` (dict): Verified claims (if successful)
- `subject` (str): SS58 address from token
- `public_key` (dict): Public key in various formats
  - `raw_hex` (str): Hex encoded public key
  - `raw_base64` (str): Base64 encoded public key
  - `pem` (str): PEM format public key
- `did_document` (dict): DID document (if `fetch_did=True` and successful)
- `error` (str): Error message (if verification failed)

## Requirements

- Python >= 3.8
- PyJWT >= 2.8.0
- cryptography >= 41.0.0
- base58 >= 2.1.1
- httpx >= 0.25.0

## License

MIT