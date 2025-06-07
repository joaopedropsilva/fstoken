from argparse import Namespace
from typing import NewType

from src.file import File


OpResult = NewType("OpResult", tuple[str, str])


class BaseOp:
    def __init__(self, args: Namespace):
        self._args = args

    def run_unpriviledged(self) -> None:
        return

    def run_priviledged(self) -> OpResult:
        return "", ""


class Delete(BaseOp):
    def __init__(self, args: Namespace):
        super().__init__(args)

    def run_unpriviledged(self) -> None:
        super().run_unpriviledged()

    def run_priviledged(self) -> OpResult:
        return super().run_priviledged()


class Invoke(BaseOp):
    def __init__(self, args: Namespace):
        super().__init__(args)

    def run_priviledged(self) -> OpResult:
        return super().run_priviledged()


class Add(BaseOp):
    def __init__(self, args: Namespace):
        super().__init__(args)

    def run_unpriviledged(self) -> None:
        super().run_unpriviledged()

    def run_priviledged(self) -> OpResult:
        return super().run_priviledged()


class Delegate(Add):
    def __init__(self, args: Namespace):
        super().__init__(args)

    def run_priviledged(self) -> OpResult:
        return super().run_priviledged()


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

