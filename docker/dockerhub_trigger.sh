#!/bin/bash

curl -s -H "Content-Type\: application/json" --data '{"source_type": "Branch", "source_name": "master"}' -X POST $DOCKER_HUB_TRIGGER_URL
curl -s -H "Content-Type: application/json" --data '{"source_type": "Tag", "source_name": "'"$TRAVIS_TAG"'"}' -X POST $DOCKER_HUB_TRIGGER_URL