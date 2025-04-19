#!/bin/bash

# print the container IP
echo Container IP: $(hostname -i)

# then run bash
exec bash
