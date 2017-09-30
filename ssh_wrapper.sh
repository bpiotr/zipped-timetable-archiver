#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

exec /usr/bin/ssh -o StrictHostKeyChecking=no -i "$DIR/ssh_key" "$@"
