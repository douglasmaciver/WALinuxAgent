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
import azurelinuxagent.common.authztoken as authztoken

POLICY_RUNCOMMAND_ENABLE = """
{
    "requestedState": "enabled",
    "properties": {
    "publisher": "Microsoft.CPlat.Core.RunCommandLinux",
    "type": "Microsoft.CPlat.Core.RunCommandLinux",
    "typeHandlerVersion": "1.0.3"
    }
}
"""
POLICY_OMSAGENT_ENABLE = """
{
    "requestedState": "enabled",
    "properties": {
    "publisher": "Microsoft.EnterpriseCloud.Monitoring.OmsAgentForLinux",
    "type": "Microsoft.EnterpriseCloud.Monitoring.OmsAgentForLinux",
    "typeHandlerVersion": "1.13.40"
    }
}
"""
POLICY_CUSTOMSCRIPT_ENABLE = """
{
    "requestedState": "enabled",
    "properties": {
    "publisher": "Microsoft.Azure.Extensions.customScript",
    "type": "Microsoft.Azure.Extensions.customScript",
    "typeHandlerVersion": "2.1.6"
    }
}
"""
POLICY_DSCFORLINUX_ENABLE = """
{
    "requestedState": "enabled",
    "properties": {
    "publisher": "Microsoft.OSTCExtensions.DSCForLinux",
    "type": "Microsoft.OSTCExtensions.DSCForLinux",
    "typeHandlerVersion": "3.0.0.5"
    }
}
"""
def create_standard_tokens(provider: authztoken.AuthzTokenProvider):
    """Utility function that creates a set of standard tokens."""
    print(provider.create_token(POLICY_RUNCOMMAND_ENABLE, "Microsoft.CPlat.Core.RunCommandLinux"))
    print(provider.create_token(POLICY_OMSAGENT_ENABLE, "Microsoft.EnterpriseCloud.Monitoring.OmsAgentForLinux"))
    print(provider.create_token(POLICY_CUSTOMSCRIPT_ENABLE, "Microsoft.Azure.Extensions.customScript"))
    print(provider.create_token(POLICY_DSCFORLINUX_ENABLE, "Microsoft.OSTCExtensions.DSCForLinux"))


def create_tokens(tokens_dir: str, private_key: str) -> bool:


    provider = authztoken.AuthzTokenProviderSymmetric(
            tokens_dir,
            private_key,
    )
    create_standard_tokens(provider)
    return True

# def _dir_path(string):
#     if os.path.isdir(string):
#         return string
#     else:
#         raise NotADirectoryError(string)

# TODO: support ~ in directory path.
# TODO: find a better way to handle default for dir.
def main() -> int:
    parser = argparse.ArgumentParser(description='authz token services')
    parser.add_argument('--dir', nargs=1, type=str, default=[""],
                        help='directory where tokens are')
    # TODO: Improve default key scheme.
    parser.add_argument('--priv', nargs=1, type=str,  default="authz fake sym key",
                        help='private key for signing')                    
    parser.add_argument('--createStd', action='store_true', 
                        help="create standard tokens")
    # parser.add_argument('--store', action='store_true', default=True
    #                     help="create standard tokens")


    args = parser.parse_args()

    if args.dir[0] == "":
        tokens_dir = os.path.join(os.getcwd(), "authz")
    else:
        tokens_dir = dir[0]
    if args.createStd :
        return create_tokens(tokens_dir, args.priv)
    # if args.store:
    #     return store_token(tokens_dir, args.token)

    return 0

if __name__ == '__main__':
    sys.exit(main())