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
# pylint: disable=too-few-public-methods, no-else-return

"""Module test_authz provides testing for the authz module.
"""
import json

from azurelinuxagent.common import event, logger
import azurelinuxagent.common.authz as authz
import azurelinuxagent.common.authztoken as authztoken
from azurelinuxagent.common.event import EVENTS_DIRECTORY, WALAEventOperation
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION
from tests.tools import (
    AgentTestCase,
    data_dir,
    load_data,
    patch,
    skip_if_predicate_true,
)
from tests.utils.event_logger_tools import EventLoggerTools

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
        "foobar" : "1597"
        },
    "protectedSettings": {
        "commandToExecute": "MIIBOwIBAAJBALx/Gl6fp02bVuoJwx7w0NT+doY9PP/8GTW6qNrrL/WPpVlxe/hy",
        "fileUris": "v4ECIQDgBd37UPcPCvE7sqgABj9BzohIu40+I1IEKdLfmvshtQIhANdnDBbR14JM"  
    }
    }
}
"""
EXT_FUBAR_JSON = """
{
    "fu": "bar",
    "type": "extensions"
}
"""
POLICY_CUSTOM_SCRIPT_GOOD_VERSION = """
{
    "requestedState": "enabled",
    "properties": {
    "publisher": "Microsoft.Azure.Extensions",
    "type": "CustomScript",
    "typeHandlerVersion": "2.1"
    }
}
"""
POLICY_RUNCOMMAND_GOOD_VERSION = """
{
    "requestedState": "enabled",
    "properties": {
    "publisher": "Microsoft.CPlat.Core.RunCommandLinux",
    "type": "Microsoft.CPlat.Core.RunCommandLinux",
    "typeHandlerVersion": "1.0.3"
    }
}
"""
POLICY_CUSTOM_SCRIPT_FAKE_VERSION = """
{
    "requestedState": "enabled",
    "properties": {
    "publisher": "Microsoft.Azure.Extensions",
    "type": "CustomScript",
    "typeHandlerVersion": "3.0"
    }
}
"""
# TODO: Get test dir from test env.
LIB_DIR = "/var/lib/waagent"

class MockLogger:
    def __init__(self):
        self.info = print


# ext_handler_i in prod code
class MockExtHandlerInstance:
    def __init__(self, _policy: str) -> None:
        policy = json.loads(_policy)
        self.properties = policy["properties"]
        self.ext_handler = MockExtension(_policy)
        self.name = self.properties["publisher"]
        self.version = self.properties["typeHandlerVersion"]
        # self.publicSettings = self.properties["settings"]
        self.logger = MockLogger()


#    def get_extension_full_name(self, extension: str) -> str:
#        return extension.publisher + "." + extension.name

# TODO: DRY: property retrieval
class MockExtension:
    def __init__(self, policy: str) -> None:
        policy = json.loads(policy)
        self.properties = policy["properties"]

        self.name = self.properties["type"]
        self.version = self.properties["typeHandlerVersion"]
        # self.publicSettings = self.properties["settings"]


# def mock_add_event(operation: str, is_success: bool, message: str, log_event: bool):
#     print("add_event " + " " + op + " " + message)


class TestAuthz(AgentTestCase):
    def setUp(self):
        AgentTestCase.setUp(self)
        # TODO: test for asymm provider
        self.provider = authztoken.AuthzTokenProviderSymmetric(
            authz.get_authz_lib_dir(LIB_DIR),
            authz.get_authz_crypto_private_key(),
        )

    # @patch("azurelinuxagent.common.event.EventLogger")
    # @patch("azurelinuxagent.common.logger.error")
    # @patch("azurelinuxagent.common.logger.warn")
    # @patch("azurelinuxagent.common.logger.info")
    # @patch("azurelinuxagent.ga.exthandlers.add_event")
    # def test_should_log_errors_if_failed_operation(
    #     self,
    #     mock_logger_info,
    #     mock_logger_warn,
    #     mock_logger_error,
    #     mock_reporter,
    #     mock_add_event,
    # ):
    #     mock_reporter.event_dir = None
    #     mock_add_event(
    #         "dummy name",
    #         version=CURRENT_VERSION,
    #         op=WALAEventOperation.AgentBlacklisted,
    #         is_success=False,
    #         message="dummy event message",
    #         reporter=mock_reporter,
    #     )

    #     self.assertEqual(1, mock_logger_error.call_count)
    #     self.assertEqual(1, mock_logger_warn.call_count)
    #     self.assertEqual(0, mock_logger_info.call_count)

    #     args = mock_logger_error.call_args[0]
    #     self.assertEqual(
    #         ("dummy name", "Download", "dummy event message", 0), args[1:]
    #     )

    def process_authorization(self, policy, op_mode: str):
        mockext_handler_i = MockExtHandlerInstance(policy)
        mockextension = MockExtension(policy)
        authz.process_authorization_for_ext_handler(
            mockext_handler_i, mockextension, op_mode
        )

    @patch("azurelinuxagent.common.event.EventLogger")
    @patch("azurelinuxagent.common.logger.error")
    @patch("azurelinuxagent.common.logger.warn")
    @patch("azurelinuxagent.common.logger.info")
    @patch("azurelinuxagent.ga.exthandlers.add_event")
    def test_should_be_authorized(
        self,
        mock_logger_info,
        mock_logger_warn,
        mock_logger_error,
        mock_reporter,
        mock_add_event,
    ):
        policy = POLICY_CUSTOM_SCRIPT_GOOD_VERSION
        token_file = self.provider.create_token(policy)
        self.process_authorization(
            policy, authz.AuthzOperationMode.EnabledFailClosed
        )
        self.provider.remove_token(token_file)

        self.assertEqual(0, mock_logger_error.call_count)
        self.assertEqual(1, mock_logger_warn.call_count)
        self.assertEqual(0, mock_logger_info.call_count)

        # args = mock_logger_error.call_args[0]
        # self.assertEqual(
        #     ("dummy name", "Download", "dummy event message", 0), args[1:]
        # )

    # TODO: When initial debugging is done, this test should be enabled.
    # @patch("azurelinuxagent.common.event.EventLogger")
    # @patch("azurelinuxagent.common.logger.error")
    # @patch("azurelinuxagent.common.logger.warn")
    # @patch("azurelinuxagent.common.logger.info")
    # @patch("azurelinuxagent.ga.exthandlers.add_event")
    # def test_should_be_unauthorized_and_raise_exception(
    #         self,
    #         mock_logger_info,
    #         mock_logger_warn,
    #         mock_logger_error,
    #         mock_reporter,
    #         mock_add_event
    #     ):
    #     policy = POLICY_CUSTOM_SCRIPT_FAKE_VERSION
    #     token_file = self.provider.create_token(policy)
    #     with self.assertRaises(authz.ExtensionsAuthorizationError):
    #         self.process_authorization(policy,
    #             authz.AuthzOperationMode.EnabledFailClosed)
    #     self.provider.remove_token(token_file)

    @patch("azurelinuxagent.common.event.EventLogger")
    @patch("azurelinuxagent.common.logger.error")
    @patch("azurelinuxagent.common.logger.warn")
    @patch("azurelinuxagent.common.logger.info")
    @patch("azurelinuxagent.ga.exthandlers.add_event")
    def test_should_be_unauthorized_and_not_raise_exception(
            self,
            mock_logger_info,
            mock_logger_warn,
            mock_logger_error,
            mock_reporter,
            mock_add_event
        ):
        policy = POLICY_CUSTOM_SCRIPT_FAKE_VERSION
        token_file = self.provider.create_token(policy)
        self.process_authorization(policy,
            authz.AuthzOperationMode.EnabledFailOpen)
        self.provider.remove_token(token_file)
