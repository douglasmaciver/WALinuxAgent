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
# Requires "pyJWT"
#
# pylint: disable=too-few-public-methods, no-else-return

"""Module authztoken provides authorization and processing logic for
determining if actions are allowed/denied according to configured authority.
"""

import os
import json
import uuid
from typing import Any
from abc import ABCMeta, abstractmethod

import jwt


AUTHZTOKEN_HEADER_NAME = "authztoken_header"
AUTHZTOKEN_PAYLOAD_NAME = "authztoken_payload"

AUTHZTOKEN_FILE_SUFFIX = ".authz"

# class AuthzTokenAlgorithm(str):
HS256 = "HS256"
RS256 = "RS256"


class AuthzTokenNote:
    """Represents the core object of authorizations.
    header is a json string describing authztoken metadata.
    payload is a json string containing application-defined elements.
    """

    def __init__(self, header: str, payload: str) -> None:
        self.header = header
        self.payload = payload

    @staticmethod
    def create_new_id() -> str:
        """Creates a new id using uuid."""
        return str(uuid.uuid4())


class AuthzTokenEncoder(metaclass=ABCMeta):
    """ABC for authorization encoders."""

    @abstractmethod
    def encode(self, note: AuthzTokenNote) -> str:
        """Encodes note and returns a token."""


class AuthzTokenDecoder(metaclass=ABCMeta):
    """ABC for authorization decoders."""

    @abstractmethod
    def decode(self, token: str) -> AuthzTokenNote:
        """Decodes a token and returns a note."""


class AuthzTokenJWTEncoder(AuthzTokenEncoder):
    """Simple wrapper class for pyJWT encoding."""

    def __init__(self, key: str, algorithm: str) -> None:
        self.key = key
        self.algorithm = algorithm

    # TODO: JWT expiry setting
    def encode(self, note: AuthzTokenNote) -> str:
        """Decodes JWT and returns payload."""
        return jwt.encode(
            {
                AUTHZTOKEN_HEADER_NAME: json.dumps(note.header),
                AUTHZTOKEN_PAYLOAD_NAME: json.dumps(note.payload),
            },
            self.key,
            algorithm=self.algorithm,
        )


class AuthzTokenJWTDecoder(AuthzTokenDecoder):
    """Simple wrapper class for pyJWT decoding."""

    def __init__(self, key: str) -> None:
        self.key = key

    def decode(self, token: str) -> AuthzTokenNote:
        """Decodes JWT and returns payload."""
        #        header = jwt.get_unverified_header(authorization)
        #        algorithms = "[" + header['alg'] + "]"
        decoded = jwt.decode(token, self.key, algorithms=[HS256, RS256])
        if decoded:
            return AuthzTokenNote(
                json.loads(decoded[AUTHZTOKEN_HEADER_NAME]),
                json.loads(decoded[AUTHZTOKEN_PAYLOAD_NAME]),
            )
        else:
            return AuthzTokenNote("", "")


class AuthzTokenCreator:
    """Creates authorizations."""

    def __init__(self, encoder: AuthzTokenEncoder) -> None:
        """encoder set now. payload set before write to storage."""
        self.encoder = encoder
        self.note = AuthzTokenNote("", "")

    # TODO: Set note properties.

    def to_store(self, store: Any) -> None:
        """Encodes note and stores token in io."""
        store.write(self.encoder.encode(self.note))


class AuthzTokenValidator:
    """Validates authorizations."""

    def __init__(self, decoder: AuthzTokenDecoder) -> None:
        self.decoder = decoder

    def from_store(self, store: Any) -> AuthzTokenNote:
        """Reads token and decodes note."""
        return self.decoder.decode(store.read())


class AuthzTokenProvider:
    """Provides authorization and processing features for actions and parameters."""

    def __init__(
        self,
        tokens_dir: str,
        pub_key: str,
        pri_key: str,
        algorithm: str,
    ) -> None:
        """authztoken_tokens_dir expects the full os path."""
        self.tokens_dir = tokens_dir
        self.pub_key = pub_key
        self.pri_key = pri_key
        self.algorithm = algorithm

        # TODO: Not the best place for this.
        if not os.path.isdir(self.tokens_dir):
            os.mkdir(self.tokens_dir)

    @staticmethod
    def create_new_note_id() -> str:
        """Wrapper API function to hide AuthzTokenNote."""
        return AuthzTokenNote.create_new_id()

    def create_token(self, payload: str, filename_override: str = None) -> str:
        """Create a token file given a payload."""
        note_id = AuthzTokenNote.create_new_id()
        encoder = AuthzTokenJWTEncoder(self.pri_key, self.algorithm)
        creator = AuthzTokenCreator(encoder)
        # TODO: Develop "cmd"
        note_header = {"noteID": note_id, "cmd": "enable"}
        creator.note = AuthzTokenNote(str(note_header), payload)

        if not filename_override:
            filename = note_id + AUTHZTOKEN_FILE_SUFFIX 
        else:
            filename = filename_override + AUTHZTOKEN_FILE_SUFFIX  


        token_file_path = os.path.join(self.tokens_dir, filename)
        with open(token_file_path, "wb") as token_file_out:
            creator.to_store(token_file_out)
        return token_file_path

    def read_note(self, token_file_path: str) -> AuthzTokenNote:
        """Read a token file and returns a validated note."""
        decoder = AuthzTokenJWTDecoder(self.pub_key)
        validator = AuthzTokenValidator(decoder)
        with open(token_file_path, "r") as token_file_in:
            return validator.from_store(token_file_in)

    def read_payload(self, token_file_path: str) -> str:
        """Read a token file and return a payload."""
        note = self.read_note(token_file_path)
        return note.payload
    
    def remove_token(self, token_file_path: str) -> None:
        """Remove a token file."""
        os.remove(token_file_path)

    def find_token(self, validate_action: Any, action: Any) -> bool:
        """Searches AuthzTokenProvider's working directory for token with matching
        policy.
        """
        for file_desc in os.listdir(self.tokens_dir):
            note = self.read_note(os.path.join(self.tokens_dir, file_desc))
            policy = json.loads(note.payload)
            if validate_action(action, policy):
                return True

        # If we get here, matching token was not found.
        return False

    def display_tokens(self) -> None:
        """Displays tokens in working directory."""
        for file_desc in os.listdir(self.tokens_dir):
            note = self.read_note(os.path.join(self.tokens_dir, file_desc))
            policy = json.loads(note.payload)
            print(policy)

    def is_authorized(self, validate_action: Any, action: Any) -> bool:
        """Determines if an action is authorized according to policy."""
        return self.find_token(validate_action, action)


class AuthzTokenProviderSymmetric(AuthzTokenProvider):
    """Provides authorization services with a symmetric key."""

    def __init__(self, authztoken_tokens_dir: str, sym_key: str) -> None:
        """authztoken_tokens_dir expects the full os path."""
        super().__init__(authztoken_tokens_dir, sym_key, sym_key, HS256)


class AuthzTokenProviderAsymmetric(AuthzTokenProvider):
    """Provides authorization services with an asymmetric key."""

    def __init__(
        self, authztoken_tokens_dir: str, pub_key: str, pri_key: str
    ) -> None:
        """authztoken_tokens_dir expects the full os path."""
        super().__init__(authztoken_tokens_dir, pub_key, pri_key, RS256)
