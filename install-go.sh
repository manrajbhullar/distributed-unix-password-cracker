#!/bin/bash

# Install mise
curl https://mise.run | sh

# Add to bash config
echo 'eval "$(~/.local/bin/mise activate bash)"' >> ~/.bashrc

# Reload shell
source ~/.bashrc

# Install Go 1.26 globally
mise use -g go@1.26
