#!/bin/bash

curl -H "Content-Type\: application/json" --data '{"source_type": "Branch", "source_name": "master"}' -X POST $DOCKER_HUB_TRIGGER_URL
