#!/bin/bash

#generates appropriate .toml configuration files from templatfrom template

players=1000

for i in $(seq 1 $players); do
    cat template_instance.toml | sed -e "s/\\$/${i}/g" > "test_instances/${i}.toml"
done
