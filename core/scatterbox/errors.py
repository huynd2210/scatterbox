"""Exception hierarchy for scatterbox.

Every error scatterbox raises on purpose derives from ScatterboxError, so
callers (the CLI, later the daemon) can catch one type and show a clean
message, while genuine bugs (KeyError, TypeError, ...) still crash loudly.
"""


class ScatterboxError(Exception):
    """Base class for all scatterbox errors."""


# -- user-facing input/validation errors ---------------------------------------


class FileTooLargeError(ScatterboxError):
    """File exceeds the soft size cap and --force-large was not given."""


class VPathExistsError(ScatterboxError):
    """Target virtual path already exists."""


class VPathNotFoundError(ScatterboxError):
    """Virtual path does not exist in the register."""


class WrongPassphraseError(ScatterboxError):
    """Passphrase failed the vault check."""


# -- placement / durability errors ---------------------------------------------


class NotEnoughProvidersError(ScatterboxError):
    """Fewer distinct usable providers available than the replica floor."""


class ChunkUnavailableError(ScatterboxError):
    """No healthy replica of a chunk could be fetched and verified.

    Raised by the read path when every replica of some chunk is missing or
    corrupt — the file cannot currently be reassembled.
    """


# -- provider-side errors (raised by adapters) ----------------------------------


class ObjectTooLargeError(ScatterboxError):
    """Object exceeds a provider's max_object_bytes."""


class ProviderFullError(ScatterboxError):
    """Provider has no capacity left for the object."""


class ProviderKilledError(ScatterboxError):
    """All operations on a hard-killed (chaos) provider fail."""
