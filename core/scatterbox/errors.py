"""Exception hierarchy for scatterbox."""


class ScatterboxError(Exception):
    """Base class for all scatterbox errors."""


class FileTooLargeError(ScatterboxError):
    """File exceeds the soft size cap and --force-large was not given."""


class NotEnoughProvidersError(ScatterboxError):
    """Fewer distinct providers available than the requested replica count."""


class VPathExistsError(ScatterboxError):
    """Target virtual path already exists."""


class VPathNotFoundError(ScatterboxError):
    """Virtual path does not exist in the register."""


class ChunkUnavailableError(ScatterboxError):
    """No healthy replica of a chunk could be fetched and verified."""


class WrongPassphraseError(ScatterboxError):
    """Passphrase failed the vault check."""


class ObjectTooLargeError(ScatterboxError):
    """Object exceeds a provider's max_object_bytes."""


class ProviderKilledError(ScatterboxError):
    """All operations on a hard-killed (chaos) provider fail."""


class ProviderFullError(ScatterboxError):
    """Provider has no capacity left for the object."""
