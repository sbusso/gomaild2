package auth

import (
	config "github.com/spf13/viper"
	. "github.com/trapped/gomaild2/pop3/structs"
	"net"
	"strings"
	"testing"
)

func initconfig() {
	//read config
	config.AddConfigPath("../../../")
	err := config.ReadInConfig()
	if err != nil {
		panic(err)
	}
	config.Set("config.loaded", true)
}

func TestProcess(t *testing.T) {
	initconfig()

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
			&Client{State: Authorization,
				Data: make(map[string]interface{})},
			Command{Verb: "AUTH", Args: "PLAIN"},
			Reply{Result: OK, Message: "authentication successful"},
		},
		{
			&Client{State: Authorization,
				Data: make(map[string]interface{})},
			Command{Verb: "AUTH", Args: "PLAIN"},
			Reply{Result: ERR, Message: "authentication failed"},
		},
		{
			&Client{State: Authorization},
			Command{Verb: "AUTH", Args: "XXX YYY ZZZ"},
			Reply{Result: ERR, Message: "unrecognized authentication method"},
		},
	}

	cmds := [][]string{
		[]string{},
		[]string{},
		[]string{},
		[]string{},
		[]string{"eHh4eABleGFtcGxlQHRlc3QuY29tAHRlc3RwYXNzd29yZA==\r\n"}, // PLAIN (valid)
		[]string{"eHh4eABlZZZZZZq13wd23uY29tAHRlc3RwYXNzd29yZA==\r\n"},   // PLAIN (invalid)
		[]string{},
	}

	l, err := net.Listen("tcp", ":1349")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	for i, testcase := range cases {

		switch len(cmds[i]) != 0 {
		case true:
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
