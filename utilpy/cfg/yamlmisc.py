#!/usr/bin/env python3

import sys
import yaml


def load_config(cfg_file):
    with open(cfg_file, "r") as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as e:
            print(e)


def main():
    # Some stuff here: unittesting, or standalone launcher
    pass


if __name__ == "__main__":
    sys.exit(main())
