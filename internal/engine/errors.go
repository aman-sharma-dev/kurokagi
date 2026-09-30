package engine

// ErrorCode is a stable, machine-readable scan error category. Messages are
// deliberately generic and must never include request credentials or bodies.
type ErrorCode string

// Error code constants identify stable sanitized execution conditions.
const (
	CodeConfigInvalid           ErrorCode = "CONFIG_INVALID"
	CodeOpenAPIInvalid          ErrorCode = "OPENAPI_INVALID"
	CodeTargetUnreachable       ErrorCode = "TARGET_UNREACHABLE"
	CodeAuthFailed              ErrorCode = "AUTH_FAILED"
	CodeScopeRejected           ErrorCode = "SCOPE_REJECTED"
	CodeRequestBudgetExhausted  ErrorCode = "REQUEST_BUDGET_EXHAUSTED"
	CodeMutationBudgetExhausted ErrorCode = "MUTATION_BUDGET_EXHAUSTED"
	CodeTimeout                 ErrorCode = "TIMEOUT"
	CodeResponseTooLarge        ErrorCode = "RESPONSE_TOO_LARGE"
	CodeUnsupportedOperation    ErrorCode = "UNSUPPORTED_OPERATION"
	CodeCancelled               ErrorCode = "CANCELLED"
	CodeInternalError           ErrorCode = "INTERNAL_ERROR"
)
