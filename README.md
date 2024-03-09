# identity-provider-service

## Description

This service is responsible for verifying a user-provided ZKP, real-world identity certificate and issuing voting permission claim.

## Endpoints

### create_identity

`create_identity` verifies a user-provided ZKP that proves the real-world identity ownership, validates this real-world identity certificate and issues a PollsCredential claim.<br><br>
Path: `POST /integrations/identity-provider-service/v1/create-identity`<br>
Payload example (proof is provided as an example and actually does not prove anything):
```json
{
  "data": {
    "id": "did:iden3:readonly:tJWarsbwqiUxHm8BPi4aYSnnj54AbuR4D2RrhkykQ",
    "document_sod": {
      "signed_attributes": "hex_string",
      "algorithm": "SHA256withRSA",
      "signature": "hex_string",
      "pem_file": "-----BEGIN CERTIFICATE-----\n{...}\n-----END CERTIFICATE-----",
      "encapsulated_content": "hex_string"
    },
    "zkproof": {
      "proof": {
        "pi_a": [
          "4486400337619062702179111506341517111494111681111222111137338836157671763417",
          "4486400337619062702179111506341517111494111681111222111137338836157671763417",
          "1"
        ],
        "pi_b": [
          [
            "4486400337619062702179111506341517111494111681111222111137338836157671763417",
            "4486400337619062702179111506341517111494111681111222111137338836157671763417"
          ],
          [
            "4486400337619062702179111506341517111494111681111222111137338836157671763417",
            "4486400337619062702179111506341517111494111681111222111137338836157671763417"
          ],
          [
            "1",
            "0"
          ]
        ],
        "pi_c": [
          "44864003376190627021791115063415171114941116811112221111373388361576717634171",
          "4486400337619062702179111506341517111494111681111222111137338836157671763417",
          "1"
        ],
        "protocol": "groth16",
        "curve": "bn128"
      },
      "pub_signals": [
        "311829949927574718572524671081106490489",
        "311829949927574718572524671081106490489",
        "4903111",
        "24",
        "1",
        "25",
        "25",
        "1",
        "25",
        "18"
      ]
    }
  }
}
```

## Issuer Node Integration

The only Issuer Node that is used is CreateCredential that issues claim. This claim is always stored in the issuer's Claims Tree (considering that the CreateCredential payload field `mtProof` is always `true`) that is automatically transited on-chain.<br><br>
`CreateCredential` payload example:
```json
{
  "credentialSchema": "https://bafybeif5xytac5352no62kalpdin3vbwp3pknijmzwd5dqgsi72jnnss6y.ipfs.w3s.link/PollsCredential.json",
  "credentialSubject": {
    "id": "did:iden3:readonly:tMF5BykcV7fiDSRi3HQSH8VHjTR24fqz2BhJHHzuY",
    "isAdult": true,
    "issuingAuthority": 4903594,
    "documentNullifier": "18586133768512220936620570745912940619677854269274689475585506675881198879027",
    "credentialHash": "8645981980787649023086883978738420856660271013038108762834452721572614684349"
  },
  "type": "PollsCredential",
  "mtProof": true,
  "signatureProof": true,
  "expiration": "2023-10-26T10:59:08Z"
}
```

## Install

  ```
  git clone github.com/rarimo/passport-identity-provider
  cd identity-provider-service
  go build main.go
  export KV_VIPER_FILE=./config.yaml
  ./main migrate up
  ./main run service
  ```

## Documentation

We do use openapi:json standard for API. We use swagger for documenting our API.

To open online documentation, go to [swagger editor](http://localhost:8080/swagger-editor/) here is how you can start it
```
  cd docs
  npm install
  npm start
```
To build documentation use `npm run build` command,
that will create open-api documentation in `web_deploy` folder.

To generate resources for Go models run `./generate.sh` script in root folder.
use `./generate.sh --help` to see all available options.

Note: if you are using Gitlab for building project `docs/spec/paths` folder must not be
empty, otherwise only `Build and Publish` job will be passed.  

## Running from docker 
  
Make sure that docker installed.

use `docker run ` with `-p 8080:80` to expose port 80 to 8080

  ```
  docker build -t github.com/rarimo/passport-identity-provider .
  docker run -e KV_VIPER_FILE=/config.yaml github.com/rarimo/passport-identity-provider
  ```

## Running from Source

* Set up environment value with config file path `KV_VIPER_FILE=./config.yaml`
* Provide valid config file
* Launch the service with `migrate up` command to create database schema
* Launch the service with `run service` command


### Database
For services, we do use ***PostgresSQL*** database. 
You can [install it locally](https://www.postgresql.org/download/) or use [docker image](https://hub.docker.com/_/postgres/).


### Third-party services


## Contact

Responsible
The primary contact for this project is  [//]: # (TODO: place link to your telegram and email)
