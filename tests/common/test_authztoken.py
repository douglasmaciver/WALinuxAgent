# Copyright 2022 Microsoft Corporation
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
#

"""Module test_authztoken provides unit testing for the authztoken module.
"""
import json
from os import stat
import unittest

import azurelinuxagent.common.authztoken as authztoken

EXT_CLI_JSON = """
{
    "name": "config-app",
    "type": "extensions",
    "location": "[resourceGroup().location]",
    "apiVersion": "2019-03-01",
    "dependsOn": [
    "[concat('Microsoft.Compute/virtualMachines/', concat(variables('vmName'),copyindex()))]"
    ],
    "tags": {
    "displayName": "config-app",
    "authorizationID": "c7c8513b-9d8d-4e85-bd3f-cdbdec8004a0",
    "packageHash" : "5lMV9V1Z6MGJZi0CICPtYRvRRkPKZhjWu0tuXlOCb0AnKzpECU3IvUeZT"
    },
    "properties": {
    "publisher": "Microsoft.Azure.Extensions",
    "type": "CustomScript",
    "typeHandlerVersion": "2.1",
    "autoUpgradeMinorVersion": true,
    "settings": {
        "fubar" : "1597"
        },
    "protectedSettings": {
        "commandToExecute": "MIIBOwIBAAJBALx/Gl6fp02bVuoJwx7w0NT+doY9PP/8GTW6qNrrL/WPpVlxe/hy",
        "fileUris": "v4ECIQDgBd37UPcPCvE7sqgABj9BzohIu40+I1IEKdLfmvshtQIhANdnDBbR14JM"  
    }
    }
}
"""

# TODO: Get test dir from test env.
LIB_DIR = "/var/lib/waagent/authz"

# TODO: Implement key retrieval from environment.
AUTHZTOKEN_FAKE_SYM_KEY = "authztoken fake sym key"


class TestAuthzToken(unittest.TestCase):
    def verify_encode_decode(
        self, payload: str, provider: authztoken.AuthzTokenProvider
    ) -> bool:
        """Run both the encode and decode steps, then test if the payload
        matches.
        """
        return payload == provider.read_payload(provider.create_token(payload))

    def test_with_json_payload(self):
        """Test encode and decode cycle with an JSON payload."""
        symm = authztoken.AuthzTokenProviderSymmetric(
            LIB_DIR, AUTHZTOKEN_FAKE_SYM_KEY
        )
        payload = EXT_CLI_JSON

        # TODO: Test asymmetric key
        # verify_encode_decode(payload, asymm)
        self.assertTrue(self.verify_encode_decode(payload, symm))
