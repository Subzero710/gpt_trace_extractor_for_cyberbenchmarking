class TraceRunnerError(RuntimeError):
    pass


class BatchCircuitBreaker(TraceRunnerError):
    """Failure that must stop the whole batch instead of advancing tasks."""


class BrowserConnectionError(BatchCircuitBreaker): pass
class BrowserIdentityError(BatchCircuitBreaker): pass
class AuthenticationRequired(BatchCircuitBreaker): pass
class RateLimited(BatchCircuitBreaker):
    def __init__(
        self,
        message: str,
        *,
        retry_after_seconds: float | None = None,
        endpoint: str | None = None,
        method: str | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds
        self.endpoint = endpoint
        self.method = method
        self.request_id = request_id

    def retry_delay(self, default_seconds: float, *, maximum_seconds: float) -> float:
        # A server-provided Retry-After is authoritative and must never be
        # shortened by a local polling/backoff ceiling. The maximum applies only
        # to our synthetic fallback when the server did not provide a delay.
        value = self.retry_after_seconds
        if value is not None and value >= 0:
            return float(value)
        return max(0.0, min(float(default_seconds), float(maximum_seconds)))
class AccessDenied(BatchCircuitBreaker): pass
class SiteChallengeFailed(BatchCircuitBreaker): pass
class AmbiguousSubmission(BatchCircuitBreaker): pass
class ConcurrentTurnError(BatchCircuitBreaker): pass
class ConcurrentRunnerError(BatchCircuitBreaker): pass
class ClipboardUnavailable(BatchCircuitBreaker): pass
class FatalUIState(BatchCircuitBreaker): pass
class EnvironmentDrift(BatchCircuitBreaker): pass
class ModelMismatch(BatchCircuitBreaker): pass
class ConversationError(BatchCircuitBreaker): pass
class ConversationNotFound(ConversationError): pass
class ConversationStreamError(BatchCircuitBreaker): pass
class ConversationStreamTimeout(ConversationStreamError): pass
class ConversationStreamAborted(ConversationStreamError): pass
class ConversationStreamProtocolError(ConversationStreamError): pass
class ConversationStreamIncomplete(ConversationStreamError): pass
class RecoveryIncomplete(BatchCircuitBreaker): pass
class AppInfrastructureError(BatchCircuitBreaker): pass
class AppRegistryError(BatchCircuitBreaker): pass
class StorageError(BatchCircuitBreaker): pass
class StorageConflict(StorageError): pass


class ChatGPTUIError(TraceRunnerError): pass


class AppUnavailable(TraceRunnerError):
    """Task-specific requested App is not available or confirmable in the UI."""


class BenchmarkError(TraceRunnerError): pass
