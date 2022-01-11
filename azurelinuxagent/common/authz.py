# Microsoft Azure Linux Agent
#
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

"""authz is the integration module for authorization tokens that
provides processing logic for determining if actions are allowed/denied
according to the configured authority.

Only authz interacts directly with the general purpose authztoken module. While authz
interacts with both azurelinuxagent and authztoken modules, azurelinuxagent modules
don't interact with authztoken directly.

As azurelinuxagent's adoption of authz increases, many of the configuration and
environment settings coded in this module will move to their respective areas.
"""

import traceback
import json
from typing import Any
import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.logger as logger
import azurelinuxagent.common.authztoken as authztoken
from azurelinuxagent.common.protocol.restapi import Extension
from azurelinuxagent.common.exception import ExtensionError
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.event import add_event, WALAEventOperation

# TODO: Move this to azurelinuxagent.common.conf
AUTHZ_LIB_DIR = "authz"


def get_authz_lib_dir(base_dir: str) -> str:
    return base_dir + "/" + AUTHZ_LIB_DIR


# TODO: Implement key retrieval from environment.
AUTHZ_FAKE_SYM_KEY = "authz fake sym key"


def get_authz_crypto_private_key() -> str:
    return AUTHZ_FAKE_SYM_KEY


ACTION_EXT_ENABLED = """
{
    "requestedState": "enabled", 
    "properties": {
    "publisher": "Microsoft.Azure.Extensions",
    "type": "CustomScript",
    "typeHandlerVersion": "2.1"
    }
}
"""


class ExtensionsAuthorizationError(ExtensionError):
    """
    Error raised when an extension action is unauthorized.
    """


class AuthzOperationMode():
    """
    The Authz framework is disabled, no checks are processed. If the Authz
    framework is enabled, failed authorizations are handled in two ways:
    Authz can be configured to "fail open" or "fail closed". In fail-open mode,
    actions that are not authorized are logged/evented, but the action is allowed
    to proceed. In fail-closed mode, actions that are not authorized raise an
    exception.
    """

    Disabled = ustr("disabled")
    EnabledFailOpen = ustr("enabledfailopen")
    EnabledFailClosed = ustr("enabledfailclosed")
    All = [Disabled, EnabledFailOpen, EnabledFailClosed]


def validate_action(policy, action):
    """Determines if policy is a subset of action."""
    if isinstance(policy, dict):
        return all(
            validate_action(v, action.get(k)) for k, v in policy.items()
        )
    else:
        return policy == action


def process_authorization_ext_handler(
    ext_handler_i: Any,
    extension: Extension,
    op_mode: str = AuthzOperationMode.EnabledFailOpen,
) -> Any:
    """Process authorization for extension handlers.
    Processing may include modification of extension returned.
    """
    # TODO: Implement operational configuration override with conf.

    try:
        if op_mode == AuthzOperationMode.Disabled:
            return extension

        provider = authztoken.AuthzTokenProviderSymmetric(
            get_authz_lib_dir(conf.get_lib_dir()),
            get_authz_crypto_private_key()
        )
        action = json.loads(ACTION_EXT_ENABLED)
        # TODO: set requestedState
        properties = action["properties"]
        properties["publisher"] = ext_handler_i.ext_handler.name
        properties["type"] = extension.name
        properties["typeHandlerVersion"] = ext_handler_i.ext_handler.version
        is_authorized = provider.is_authorized(validate_action, action)
        #ext_handler_i.logger.info("[Authz: {0} action]: {1}", message, action)

        event_message = "[Authz: {status} action]: {action}".format(
            status="authorized" if is_authorized else "unauthorized", action=action)

        # TODO: Add special Authz operation.
        add_event(
            op=WALAEventOperation.ExtensionProcessing,
            is_success=is_authorized,
            message=event_message,
            log_event=True,
        )
        if op_mode == AuthzOperationMode.EnabledFailClosed:
            raise ExtensionsAuthorizationError(event_message)

        # TODO: Future: extension may be modified if some settings are encrypted
        return extension
    except Exception as e:
        msg = "authz exception: {0}: {1}".format(
            ustr(e), traceback.format_exc()
        )
        logger.info(msg)
        # TODO: remove after initial debugging
        # TODO: develop fail-open, fail-closed concept
        # TODO: raise exception
        return extension
