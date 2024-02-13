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
      "signed_attributes": "3148301506092a864886f70d01090331080606678108010101302f06092a864886f70d0109043122042098047563f072d835b5eb7b434a3c9e678c960e083bf3bb42e1a6301dd39688fe",
      "algorithm": "SHA256withRSA",
      "signature": "4f7bd752b7d701b85c32a931be0f603543a2d914cec2da98f0c36d63187400c55e2bcfbbb822b235ab56e6635a9c331c4b638cfd8b34bf2fa75c5c5f1e8cba74bf5071bc9a42cb2109633a6d2234d7f408b7a1ad86140f17e8db8691c803106e6ed01834a4931188c4338f0e25ed469d91d35fc12783d16e6efd3475e9e3861da23015847841ac9b3e75942a0485b244af42d955dcab5ea94bfec961b1c0903f08574238fca5691289813e16fb3dc395879d50fad6e1f915f1dde14a1f72f52406ef5feb5c9c536a4930c5da2c0956071d015b93f1ad817ca5e52de389f0f9f4d3ea90767cc4f1cc008994c729bd5af72e022b46ae21b78296108b70eaf3951285e115ec6d43a681d4b5115cb7e8c8b97899799f0f30506deac8f7520f1d5ab92240fbd8fd0a58b28fc942dc1bb70110f336640aa9ce610d57a396e2c6313a95412542a1a41ad0160e8a2be16eff9169a2021d2a1e18f52fbdfcf33bedcab455ed77452812b2f730052ad37a23f76f5d1616dfa1613867f84c943bcdec1ab00bb3e7aa49ddf8d5884ee5a57d744b76cb3be3c0c62e3a88ab64c53eed2c1d0aac7b630d1624aadfb23c9ce5f42155507645ebbce5bddbe40572858f3f0fd551ea4084af0d1219ba2e440cc09f9b88154b8a4451f6f9772abcdee80fe1b9a1d159aa1d7882a10c50968cb0558f371f4f147b582a422f661c5defb32bbc83d1d438",
      "pem_file": "-----BEGIN CERTIFICATE-----\n{...}\n-----END CERTIFICATE-----",
      "encapsulated_content": "3082014e020100300d060960864801650304020105003082013830250201010420ea98438932bf341bbd2d767e4375c4795e936bd92e75a755e1c305cb480a499c30250201020420a2d487c529a91a12aa98e6ea4c6f2ffeac541ab38b4fd03dec6c38731a1d36e930250201030420055bc2003da69e9815cfdc0e10cab2c2cea63c1f4bd4dbf41321947ca808ddec3025020105042077a8abea04916096843b9f54f0a9f4c4deb7787afc4e59cf6b5990f257e309883025020107042009994f3107984bca7ca55860fd300e2c271c65a2896251cb671e4faf2992f9c7302502010d04203925215d442e9fac6cd9658a3b30cb8b9f61d193971a7c6870b48c72fb12ae20302502010e0420af3c25b373904cafa706d10485ba2dd70557f7be352fe384fedcaa278e850f6f302502010f0420b021a96350b53f1e1e2a701c7e1a7e33a5555ae34479ab175a071aa7f77be706"
    },
    "zkproof": {
      "proof": {
        "pi_a": [
          "4486400337619062702179365506341517219494617681140222729537338836157671763417",
          "18040777690993081440051963302217516393665782853131037258627873093114582471763",
          "1"
        ],
        "pi_b": [
          [
            "16934350240548383168617480752064545886648124524261092141306400180842929667782",
            "8328826859513236175957966756490179747578331660506136497059417713087736718083"
          ],
          [
            "17307042043047414670966167596962329112137506108316641574912005237404122000079",
            "11176190188561546691687353016179614468284107512537586814251416611816570379580"
          ],
          [
            "1",
            "0"
          ]
        ],
        "pi_c": [
          "19084464556570719867323893826192085065681479245099043115532243791000207003087",
          "6857969902801516271974251398591102815580777707996180754520864189754517983374",
          "1"
        ],
        "protocol": "groth16",
        "curve": "bn128"
      },
      "pub_signals": [
        "311829949927574718572524671081106490489",
        "125712886666704113030568989702153193884",
        "4903594",
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
  git clone github.com/RarimoVoting/identity-provider-service
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
  docker build -t github.com/RarimoVoting/identity-provider-service .
  docker run -e KV_VIPER_FILE=/config.yaml github.com/RarimoVoting/identity-provider-service
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

Responsible Roman Harazha
The primary contact for this project is  t.me/overcoatocracy
