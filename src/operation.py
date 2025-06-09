from argparse import Namespace

from src.file import File
from src.helpers import OpResult
from src.fskeys import Fskeys
from src.keystore import Keystore


class BaseOp:
    def __init__(self, args: Namespace):
        self._args = args
        self._requester_has_access_to_file = False

    def run_unpriviledged(self) -> str:
        return ""

    def run_priviledged(self) -> OpResult:
        if not self._requester_has_access_to_file:
            return f"Operation not allowed for user in {self._args.file}", ""

        return "", ""


class Delete(BaseOp):
    def __init__(self, args: Namespace):
        super().__init__(args)

    def run_unpriviledged(self) -> str:
        revocation_err = File.revoke_fstoken_access(self._args.file)
        if revocation_err != "":
            return revocation_err

        self._requester_has_access_to_file = True

        return ""

    def run_priviledged(self) -> OpResult:
        (access_error, _) = super().run_priviledged()
        if access_error != "":
            return access_error, ""

        (was_encrypted, prevkey) = Keystore.search_entry_state(self._args.file)
        if prevkey == "":
            return f"File not found in {Keystore.STORE_FILENAME}", ""

        Keystore.change_entry(self._args.file, delete=True)

        if was_encrypted:
            File.decrypt(self._args.file, filekey)

        return "", ""


class Invoke(BaseOp):
    def __init__(self, args: Namespace):
        super().__init__(args)

    def run_priviledged(self) -> OpResult:
        (was_encrypted, prevkey) = Keystore.search_entry_state(self._args.file)
        if prevkey == "":
            return f"File not found in {Keystore.STORE_FILENAME}", ""

        try:
            initial_grant = ""
            extracted_grant = Token.validate(args.token, filekey)
            if extracted_grant == "":
                return f"Invalid access token to {self._args.file}", ""
        except (AssertionError, KeyError) as err:
            return err, "" 

        # open $EDITOR with permissions

        return "", ""


class Add(BaseOp):
    def __init__(self, args: Namespace):
        super().__init__(args)

    def run_unpriviledged(self) -> str:
        grant_err = File.grant_fstoken_access(self._args)
        if grant_err != "":
            return grant_err

        self._requester_has_access_to_file = True

        return ""

    def run_priviledged(self) -> OpResult:
        (access_err, _) = super().run_priviledged()
        if access_err != "":
            return access_err, ""

        (was_encrypted, prevkey) = Keystore.search_entry_state(self._args.file)

        newkey = Keystore.change_entry(self._args.file,
                                       encrypt=self._args.encrypt,
                                       rotate_key=self._args.rotate,
                                       delete=False)

        if was_encrypted:
            File.decrypt(self._args.file, prevkey)
        if args.encrypt:
            File.encrypt(self._args.file, newkey)

        return "", filekey


class Delegate(Add):
    def __init__(self, args: Namespace):
        super().__init__(args)

    def run_priviledged(self) -> OpResult:
        (add_err, filekey) = super().run_priviledged()
        if add_err != "":
            return add_err, ""

        (private, _) = Fskeys.get_keys()
        try:
            token = Token.encode(private,
                                 raw_payload={"filekey": filekey,
                                              "grant": self._args.grant,
                                              "subject": self._args.subject,
                                              "proof": [self._args.token]})
        except (AssertionError, KeyError) as err:
            return err, ""

        return "", token


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

