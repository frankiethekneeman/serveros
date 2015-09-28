#!/bin/bash
rm -rf out/
jsdoc -r pieces errors lib.js -c jsdoc/conf.json
