package noop

import (
	. "github.com/trapped/gomaild2/pop3/structs"
	"testing"
)

func TestProcess(t *testing.T) {
	cases := []struct {
		c      *Client
		cmd    Command
		expect Reply
	}{
		{
			&Client{State: Authorization},
			Command{},
			Reply{Result: ERR, Message: "no action performed"},
		},
		{
			&Client{State: Transaction},
			Command{},
			Reply{Result: OK, Message: "no action performed"},
		},
	}

	for _, testcase := range cases {
		rep := Process(testcase.c, testcase.cmd)

		if testcase.expect != rep {
			t.Errorf("Expected %v, got %v\n", testcase.expect, rep)
		}
	}
}
