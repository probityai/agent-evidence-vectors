"""The input refusal shared by the reader and installed-byte checker."""


class InputError(ValueError):
    """The selected input does not meet this finite profile."""
