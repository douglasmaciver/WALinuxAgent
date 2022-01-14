#!/usr/bin/env python3

# Copyright 2020 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import os
import argparse
import uuid

AUTHZTOKEN_INCOMING_FILE_SUFFIX = ".authzap"

def store_token_from_str(token: str, filename_override: str = None) -> str:
    """Store a token given a string"""
    random_filename = str(uuid.uuid4())
    if not filename_override:
        filename = random_filename + AUTHZTOKEN_INCOMING_FILE_SUFFIX 
    else:
        filename = filename_override + AUTHZTOKEN_INCOMING_FILE_SUFFIX  

    # TODO: hard-coded "authz" is brittle. Read it from config.
    token_file_path = os.path.join(os.getcwd(), "authz", filename)
    with open(token_file_path, "w") as token_file_out:
        token_file_out.write(token)
    return token_file_path

def main() -> int:
    parser = argparse.ArgumentParser(description='authz token services')
    parser.add_argument('token_str', nargs=1, type=str,
                        help='token string')

    args = parser.parse_args()
    store_token_from_str(args.token_str[0])
    return 0

if __name__ == '__main__':
    sys.exit(main())