#!/bin/bash
set -x
node demo/masterDemo.js &
node demo/providerDemo.js &
sleep 1
time node demo/consumerDemo.js

jobs -p | xargs kill 
