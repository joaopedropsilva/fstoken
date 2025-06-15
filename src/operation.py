from argparse import Namespace
from pathlib import Path
from os import remove
from subprocess import run

from token import Token, Grants
from file import File
from helpers import Message, remove_whitespace_newline
from keystore import Keystore


class BaseOp:
    def __init__(self, args: Namespace):
        self._args = args
        self._requester_has_access_to_file = False

    def run_unpriviledged(self) -> str:
        return ""

    def run_priviledged(self) -> Message:
        if not self._requester_has_access_to_file:
            return Message(
                payload=None,
                err=f"Operation not allowed for user in {self._args.file}"
            )

        return Message(payload="", err="")


class Delete(BaseOp):
    def __init__(self, args: Namespace):
        super().__init__(args)

    def run_unpriviledged(self) -> str:
        revocation_err = File.revoke_fstoken_access(self._args.file)
        if revocation_err:
            return revocation_err

        return ""

    def run_priviledged(self) -> Message:
        (was_encrypted, prevkey) = Keystore.search_entry_state(self._args.file)
        if not prevkey:
            return Message(
                payload=None,
                err=f"File not found in {Keystore.STORE_FILENAME}"
            )

        Keystore.change_entry(self._args.file, delete=True)

        if was_encrypted:
            File.decrypt(self._args.file, prevkey)

        return Message(payload="", err="")


class Invoke(BaseOp):
    @staticmethod
    def prompt_user_with_file_editor(file_info: Message) -> Message:
        (filename, file_content, allowed_mode) = file_info.payload

        default_payload = (None, None)
        if not filename or not file_content or not allowed_mode:
            return Message(payload=default_payload,
                           err="Failed to recover file information")

        file_id = filename.split("/")[-1]
        tmp_filename = f"/tmp/temp_{file_id}"
        with open(tmp_filename, "w") as f:
            f.write(file_content)

        mode_args = ["-R"] if allowed_mode == Grants.READ.value else []
        cmd = ["vim", tmp_filename]
        cmd.extend(mode_args)
        try:
            run(cmd)
        except Exception as err:
            return Message(payload=default_payload,
                           err=f"Failed to run file editor: {repr(err)}")

        new_content = None
        with open(tmp_filename, "r") as f:
            new_content = f.read()
        remove(tmp_filename)

        return Message(payload=(filename if new_content else None, new_content), err="")

    @staticmethod
    def _get_file_content(filename: str) -> tuple[bool, str, str]:
        (is_encrypted, filekey) = Keystore.search_entry_state(filename)

        content = ""
        if is_encrypted:
            content = File.decrypt_to_read(filename, filekey)
        else:
            with open(filename, "r") as f:
                content = f.read()

        return is_encrypted, filekey, content

    @classmethod
    def update_file(cls, file_info: Message) -> None:
        (filename, new_content) = file_info.payload
        if not filename or not new_content:
            return

        (is_encrypted, filekey, old_content) = cls._get_file_content(filename)

        if new_content == old_content:
            return

        with open(filename, "w") as file:
            file.write(new_content)

        if is_encrypted and filekey:
            File.encrypt(filename, filekey)


    def __init__(self, args: Namespace):
        super().__init__(args)

    def run_priviledged(self) -> Message:
        default_payload = (None, None, None)

        (is_encrypted, filekey) = Keystore.search_entry_state(self._args.file)
        if not filekey:
            return Message(
                payload=default_payload,
                err=f"File not found in {Keystore.STORE_FILENAME}"
            )

        try:
            initial_grant = None
            extracted_grant = Token.validate(self._args.token,
                                             initial_grant,
                                             filekey)
        except (AssertionError, KeyError) as err:
            return Message(payload=default_payload, err=err)

        try:
            (_, _, file_content) = self._get_file_content(self._args.file)
        except FileNotFoundError:
            return Message(payload=default_payload, err=f"File {self._args.file} not found")
        except PermissionError:
            return Message(
                payload=default_payload,
                err=f"Could not open {self._args.file}, fstoken user not authorized"
            )

        return Message(
            payload=(self._args.file, file_content, extracted_grant.value),
            err=""
        )


class Add(BaseOp):
    def __init__(self, args: Namespace):
        super().__init__(args)

    def run_unpriviledged(self) -> str:
        grant_err = File.grant_fstoken_access(self._args.file)
        if grant_err:
            return grant_err

        self._requester_has_access_to_file = True

        return ""

    def run_priviledged(self) -> Message:
        base_op_result = super().run_priviledged()
        if base_op_result.err:
            return base_op_result

        (was_encrypted, prevkey) = Keystore.search_entry_state(self._args.file)

        newkey = Keystore.change_entry(self._args.file,
                                       encrypt=self._args.encrypt,
                                       rotate_key=self._args.rotate,
                                       delete=False)

        if was_encrypted:
            File.decrypt(self._args.file, prevkey)
        if self._args.encrypt:
            File.encrypt(self._args.file, newkey)

        return Message(payload=newkey, err="")


class Delegate(Add):
    def __init__(self, args: Namespace):
        super().__init__(args)

    def run_priviledged(self) -> Message:
        add_op_result = super().run_priviledged()
        if add_op_result.err:
            return add_op_result

        try:
            seed = remove_whitespace_newline(self._args.key)
            token = Token.encode(seed,
                                 raw_payload={"filekey": add_op_result.payload,
                                              "grant": self._args.grant,
                                              "proof": [self._args.token]})
        except (AssertionError, KeyError) as err:
            return Message(payload=None, err=err)

        return Message(payload=token, err="", hide_payload=False)


class OperationRegistry:
    @staticmethod
    def get_operation_by_args(args: Namespace) -> BaseOp:
        if args.delete:
            return Delete(args)

        is_delegation = args.grant and args.key
        if is_delegation:
            return Delegate(args)

        if args.token and not is_delegation:
            return Invoke(args)

        return Add(args)

