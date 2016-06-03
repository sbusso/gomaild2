package auth

import (
	. "github.com/trapped/gomaild2/pop3/structs"
	"net"
	"strings"
	"testing"
)

func TestProcess(t *testing.T) {
	authedClient := &Client{
		Data: make(map[string]interface{}),
	}
	authedClient.Set("authenticated", true)

	cases := []struct {
		c      *Client
		cmd    Command
		expect Reply
	}{
		{
			&Client{
				Data:  authedClient.Data,
				State: Authorization,
			},
			Command{},
			Reply{Result: ERR, Message: "already authenticated"},
		},
		{
			&Client{
				Data:  authedClient.Data,
				State: Transaction,
			},
			Command{},
			Reply{Result: ERR, Message: "bad state"},
		},
		{
			&Client{State: Transaction},
			Command{},
			Reply{Result: ERR, Message: "bad state"},
		},
		{
			&Client{State: Authorization},
			Command{},
			Reply{Result: OK, Message: "\r\n" + strings.Join([]string{"PLAIN", "LOGIN", "CRAM-MD5"}, "\r\n") + "\r\n."},
		},
		{
			&Client{State: Authorization},
			Command{Verb: "AUTH", Args: "PLAIN"},
			Reply{Result: OK, Message: "authentication successful"},
		},
	}

	cmds := [][]string{
		[]string{},
		[]string{},
		[]string{},
		[]string{},
		[]string{"eHh4eABleGFtcGxlQHRlc3QuY29tAHRlc3RwYXNzd29yZA==", "\r\n"},
	}

	l, err := net.Listen("tcp", ":1349")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	for i, testcase := range cases {

		switch i {
		case 4:
			go func(n int) {
				conn, err := net.Dial("tcp", ":1349")
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()

				if err != nil {
					t.Errorf("%v", err)
				}

				q := strings.Join(cmds[n], "")

				conn.Write([]byte(q))

			}(i)

			conn, err := l.Accept()
			if err != nil {
				t.Fatal(err)
				return
			}

			testcase.c.Conn = conn
			testcase.c.MakeReader()
		default:
		}
		rep := Process(testcase.c, testcase.cmd)
		if testcase.expect != rep {
			t.Errorf("Expected %v, got %v\n", testcase.expect, rep)
		}
	}
}
