from __future__ import annotations


class KMSError(Exception):
    """API error. `code` mirrors the AWS KMS exception names so the UI feels familiar."""

    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def access_denied(message: str = "You are not authorized to perform this operation on this key") -> KMSError:
    return KMSError("AccessDeniedException", message, 403)


def not_found(message: str = "Key not found") -> KMSError:
    return KMSError("NotFoundException", message, 404)


def invalid_state(message: str) -> KMSError:
    return KMSError("KMSInvalidStateException", message, 409)


def disabled(message: str = "This key is disabled") -> KMSError:
    return KMSError("DisabledException", message, 409)


def invalid_ciphertext(message: str = "The ciphertext blob is invalid or does not match the encryption context") -> KMSError:
    return KMSError("InvalidCiphertextException", message, 400)


def throttled(message: str = "Rate exceeded") -> KMSError:
    return KMSError("ThrottlingException", message, 429)
