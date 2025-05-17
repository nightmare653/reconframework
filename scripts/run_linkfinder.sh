#!/bin/bash
domain=$1
output=$2
LinkFinder -i https://$domain -o cli > "$output"
