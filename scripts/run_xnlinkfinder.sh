#!/bin/bash
domain=$1
output=$2
cd xnLinkFinder
python3 xnLinkFinder.py -i https://$domain -o "$output"
