package secenv

type Error struct {
	msg string
}

func NewError(msg string) *Error {
	return &Error{msg: msg}
}

func (e *Error) Error() string {
	return "secenv error: " + e.msg
}
