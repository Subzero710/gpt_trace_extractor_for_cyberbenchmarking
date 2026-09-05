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
class CompletionTimeout(TraceRunnerError):
    pass
class BenchmarkError(TraceRunnerError):
    pass
class StorageError(TraceRunnerError):
    pass
