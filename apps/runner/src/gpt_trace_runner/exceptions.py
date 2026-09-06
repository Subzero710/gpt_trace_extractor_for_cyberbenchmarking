class TraceRunnerError(RuntimeError):
    pass


class BrowserConnectionError(TraceRunnerError):
    pass


class AuthenticationRequired(TraceRunnerError):
    pass


class ChatGPTUIError(TraceRunnerError):
    pass


class ConversationError(TraceRunnerError):
    pass


class ConversationStreamError(TraceRunnerError):
    pass


class ConversationStreamTimeout(ConversationStreamError):
    pass


class ConversationStreamAborted(ConversationStreamError):
    pass


class ConversationStreamProtocolError(ConversationStreamError):
    pass


class ConversationStreamIncomplete(ConversationStreamError):
    pass


class RecoveryIncomplete(TraceRunnerError):
    pass


class RequiredToolNotUsed(TraceRunnerError):
    pass


class BenchmarkError(TraceRunnerError):
    pass


class StorageError(TraceRunnerError):
    pass
