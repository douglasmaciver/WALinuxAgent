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
    print(token_file = provider.create_token(POLICY_CUSTOMSCRIPT_ENABLE, "Microsoft.Azure.Extensions.customScript"))
    print(provider.create_token(POLICY_DSCFORLINUX_ENABLE, "Microsoft.OSTCExtensions.DSCForLinux"))
