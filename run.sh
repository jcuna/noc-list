#!/usr/bin/env sh

if [ "$1" != "" ] && [ "$1" != "test" ] && [ "$1" != "stop" ]; then
    >&2 printf "Bad argument %s.\n" "${1}"
    >&2 printf "Options:\n"
    >&2 printf "\t<no args>          -- Starts badsec server if not running and runs the app\n"
    >&2 printf "\t<stop>             -- Stop badesec server and clean ups docker stuff\n"
    >&2 printf "\t<test>             -- Run tests on the api\n"
    exit 1;
fi

NET=$(docker network ls -q --filter name=sec-net)
BAD_SEC_SERVER=$(docker ps -a -q --filter name="server.badsec.gov" --format="{{.ID}}")
NOCLIST=$(docker ps -a -q --filter name="noclist_v2_001" --format="{{.ID}}")


if [ "$1" = "stop" ]; then
  docker rm -f "$BAD_SEC_SERVER" > /dev/null 2>&1
  docker rm -f "$NOCLIST" > /dev/null 2>&1
  docker network rm "$NET" > /dev/null 2>&1
else
  if [ "$1" = "test" ]; then
    COMMAND="python tests.py"
  else
    COMMAND="python -c 'import app; app.print_noc_users()'"
  fi
  if [ -z "$NET" ]; then
    docker network create sec-net
  fi
  if [ -z "$BAD_SEC_SERVER" ]; then
    docker run -d --name server.badsec.gov --network sec-net adhocteam/noclist
  fi
  docker run \
    -t \
    -v "$(pwd)/src:/usr/local/noclist" \
    -w /usr/local/noclist \
    -e BADSEC_API=http://server.badsec.gov:8888 \
    --rm \
    --name noclist_v2_001 \
    --network sec-net \
    python:3.8.7-alpine3.12 \
    /bin/ash -c "$COMMAND"
fi
