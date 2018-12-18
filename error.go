package secenv

const (
	noTokenProvided = "no token provided"
	wrongValueType  = "wrong value type"
	noDataReturned  = "no data returned"
)

type Error struct {
	msg string
}

func (e *Error) Error() string {
	return "secenv error: " + e.msg
}
