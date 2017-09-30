#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cat $DIR/ssh_key

exec /usr/bin/ssh -o StrictHostKeyChecking=no -i "$DIR/ssh_key" "$@"
