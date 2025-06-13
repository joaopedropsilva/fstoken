from argparse import Namespace
from pathlib import Path

from src.token import Token
from src.file import File
from src.helpers import Message
from src.fskeys import Fskeys
from src.keystore import Keystore


class BaseOp:
    def __init__(self, args: Namespace):
        self._args = args
        self._requester_has_access_to_file = False

    def run_unpriviledged(self) -> str:
        return ""

    def run_priviledged(self) -> Message:
        if not self._requester_has_access_to_file:
            return Message(
                payload="",
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

        self._requester_has_access_to_file = True

        return ""

    def run_priviledged(self) -> Message:
        base_op_result = super().run_priviledged()
        if base_op_result.err:
            return base_op_result

        (was_encrypted, prevkey) = Keystore.search_entry_state(self._args.file)
        if prevkey == "":
            return Message(
                payload="",
                err=f"File not found in {Keystore.STORE_FILENAME}"
            )

        Keystore.change_entry(self._args.file, delete=True)

        if was_encrypted:
            File.decrypt(self._args.file, prevkey)

        return Message(payload="", err="")


class Invoke(BaseOp):
    def __init__(self, args: Namespace):
        super().__init__(args)

    def run_priviledged(self) -> Message:
        result = (None, None)

        (was_encrypted, prevkey) = Keystore.search_entry_state(self._args.file)
        if prevkey == "":
            return Message(
                payload=result,
                err=f"File not found in {Keystore.STORE_FILENAME}"
            )

        try:
            initial_grant = None
            extracted_grant = Token.validate(self._args.token,
                                             initial_grant,
                                             prevkey)
        except (AssertionError, KeyError) as err:
            return Message(payload=result, err=repr(err))

        try:
            file = open(Path(self._args.file), extracted_grant.value)
        except FileNotFoundError:
            return Message(payload=result, err=f"File {self._args.file} not found")
        except PermissionError:
            return Message(
                payload=result,
                err=f"Could not open {self._args.file}, fstoken user not authorized"
            )

        return Message(payload=(file.fileno(), extracted_grant.value), err="")


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

        (private, _) = Fskeys.get_keys()
        try:
            token = Token.encode(private,
                                 raw_payload={"filekey": add_op_result.payload,
                                              "grant": self._args.grant,
                                              "subject": self._args.subject,
                                              "proof": [self._args.token]})
        except (AssertionError, KeyError) as err:
            return Message(payload="", err=repr(err))

        return Message(payload=token, err="", hide_payload=False)


class OperationRegistry:
    @staticmethod
    def get_operation_by_args(args: Namespace) -> BaseOp:
        if args.delete:
            return Delete(args)

        is_delegation = args.grant and args.subject
        if args.grant and args.subject:
            return Delegate(args)

        if args.token and not is_delegation:
            return Invoke(args)

        return Add(args)

