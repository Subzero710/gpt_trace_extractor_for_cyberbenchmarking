class TraceRunnerError(RuntimeError):
    pass


class BatchCircuitBreaker(TraceRunnerError):
    """Failure that must stop the whole batch instead of advancing tasks."""


class BrowserConnectionError(BatchCircuitBreaker):
    pass


class BrowserIdentityError(BatchCircuitBreaker):
    pass


class AuthenticationRequired(BatchCircuitBreaker):
    pass


class RateLimited(BatchCircuitBreaker):
    pass


class AccessDenied(BatchCircuitBreaker):
    pass


class SiteChallengeFailed(BatchCircuitBreaker):
    pass


class AmbiguousSubmission(BatchCircuitBreaker):
    pass


class ConcurrentTurnError(BatchCircuitBreaker):
    pass


class ConcurrentRunnerError(BatchCircuitBreaker):
    pass


class ClipboardUnavailable(BatchCircuitBreaker):
    pass


class FatalUIState(BatchCircuitBreaker):
    pass


class EnvironmentDrift(BatchCircuitBreaker):
    pass


class ModelMismatch(BatchCircuitBreaker):
    pass


class ChatGPTUIError(TraceRunnerError):
    pass


class ConversationError(BatchCircuitBreaker):
    pass


class CompletionTimeout(BatchCircuitBreaker):
    pass


class ConversationStreamError(BatchCircuitBreaker):
    pass


class ConversationStreamTimeout(ConversationStreamError):
    pass


class ConversationStreamAborted(ConversationStreamError):
    pass


class ConversationStreamProtocolError(ConversationStreamError):
    pass


class ConversationStreamIncomplete(ConversationStreamError):
    pass


class RecoveryIncomplete(BatchCircuitBreaker):
    pass


class RequiredToolNotUsed(TraceRunnerError):
    pass


class AppUnavailable(TraceRunnerError):
    """Task-specific requested App is not available/confirmable in the UI."""


class BenchmarkError(TraceRunnerError):
    pass


class StorageError(BatchCircuitBreaker):
    pass


class StorageConflict(StorageError):
    pass
