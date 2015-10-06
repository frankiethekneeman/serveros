#!/bin/bash
set -x
node demo/masterDemo.js &
node demo/providerDemo.js 

jobs -p | xargs kill 
