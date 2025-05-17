#!/bin/bash

if [ "$1" == "" ]; then
    echo "Usage: ./run_recon.sh -d <domain> [--tools tool1,tool2,...] | --list <domains.txt> [--tools tool1,tool2,...]"
    exit 1
fi

# Build the Go recon engine binary
echo "⚙️ Building..."
go build -o reconengine ./cmd/main.go
if [ $? -ne 0 ]; then
    echo "❌ Build failed."
    exit 1
fi

# Initialize defaults
TOOLS="all"

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -d)
            DOMAIN="$2"
            shift 2
            ;;
        --list)
            DOMAIN_FILE="$2"
            shift 2
            ;;
        --tools)
            TOOLS="$2"
            shift 2
            ;;
        *)
            echo "❌ Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run recon
if [ -n "$DOMAIN_FILE" ]; then
    if [ ! -f "$DOMAIN_FILE" ]; then
        echo "❌ File not found: $DOMAIN_FILE"
        exit 1
    fi
    echo "📜 Scanning domains from: $DOMAIN_FILE with tools: $TOOLS"
    ./reconengine --list "$DOMAIN_FILE" --tools "$TOOLS"
elif [ -n "$DOMAIN" ]; then
    echo "🔍 Launching ReconEngine on: $DOMAIN with tools: $TOOLS"
    ./reconengine -d "$DOMAIN" --tools "$TOOLS"
else
    echo "❌ No domain or domain list provided."
    exit 1
fi
