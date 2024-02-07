#!/usr/bin/env bash

GENERATOR_IMAGE=tokend/openapi-generator:v0.1.0


GENERATED="$PWD/resources"
OPENAPI_DIR="$PWD/docs/web_deploy"
PACKAGE_NAME=resources

function printHelp {
    echo "usage: ./generate.sh [<flags>]
            script to generate resources for api

            Flags:
                  --package PACKAGE        package name of generated stuff (first line of file, by default is 'resources')
                  --image IMAGE            name of generator docker image (by default is openapi-generator)

              -h, --help                   show this help
              -p, --path-to-generate PATH  path to put generated things (by default is resources)
              -i, --input OPENAPI_DIR      path to dir where openapi.yaml is stored (by default docs/web_deploy)"
}

function parseArgs {
    while [[ -n "$1" ]]
    do
        case "$1" in
            -h | --help)
                printHelp && exit 0
                ;;
            -p | --path-to-generate) shift
                [[ ! -d $1 ]] && echo "path $1 does not exist or not a dir" && exit 1
                GENERATED=$1
                ;;
            --package) shift
                [[ -z "$1" ]] && echo "package name not specified" && exit 1
                PACKAGE_NAME=$1
                ;;
            -i | --input) shift
                [[ ! -f "$1/openapi.yaml" ]] && echo "file openapi.yaml does not exist in $1 or not a file" && exit 1
                OPENAPI_DIR=$1
                ;;
            --image) shift
                [[ "$(docker images -q $1)" == "" ]] && echo "image $1 does not exist locally" && exit 1
                GENERATOR_IMAGE=$1
                ;;
        esac
        shift
    done
}

function generate {
    (cd docs && npm run build)
    docker run -v "${OPENAPI_DIR}":/openapi -v "${GENERATED}":/generated "${GENERATOR_IMAGE}" generate -pkg "${PACKAGE_NAME}" --raw-formats-as-types
    goimports -w ${GENERATED}
}

parseArgs "$@"
#echo ${OPENAPI_DIR} ${GENERATED} ${GENERATOR_IMAGE} ${PACKAGE_NAME}
generate
