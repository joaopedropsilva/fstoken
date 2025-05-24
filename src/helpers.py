def log(message: str, verbose: bool) -> None:
    if not verbose:
        return
    print(message)

