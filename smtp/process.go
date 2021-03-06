package smtp

//WARNING: Automatically generated file. DO NOT EDIT!

import (
	log "github.com/sirupsen/logrus"
	. "github.com/trapped/gomaild2/smtp/structs"
	"strings"

	"github.com/trapped/gomaild2/smtp/commands/auth"

	"github.com/trapped/gomaild2/smtp/commands/data"

	"github.com/trapped/gomaild2/smtp/commands/ehlo"

	"github.com/trapped/gomaild2/smtp/commands/helo"

	"github.com/trapped/gomaild2/smtp/commands/mail"

	"github.com/trapped/gomaild2/smtp/commands/noop"

	"github.com/trapped/gomaild2/smtp/commands/quit"

	"github.com/trapped/gomaild2/smtp/commands/rcpt"

	"github.com/trapped/gomaild2/smtp/commands/rset"

	"github.com/trapped/gomaild2/smtp/commands/starttls"
)

func Process(c *Client, cmd Command) (reply Reply) {
	switch strings.ToLower(cmd.Verb) {

	case "auth":
		reply = auth.Process(c, cmd)

	case "data":
		reply = data.Process(c, cmd)

	case "ehlo":
		reply = ehlo.Process(c, cmd)

	case "helo":
		reply = helo.Process(c, cmd)

	case "mail":
		reply = mail.Process(c, cmd)

	case "noop":
		reply = noop.Process(c, cmd)

	case "quit":
		reply = quit.Process(c, cmd)

	case "rcpt":
		reply = rcpt.Process(c, cmd)

	case "rset":
		reply = rset.Process(c, cmd)

	case "starttls":
		reply = starttls.Process(c, cmd)

	default:
		reply = Reply{
			Result:  CommandNotImplemented,
			Message: "command not implemented",
		}
	}
	if reply.Result == Ignore {
		return
	}
	log.WithFields(log.Fields{
		"id":     c.ID,
		"cmd":    cmd.Verb,
		"args":   cmd.Args,
		"result": reply.Result,
		"reply":  LastLine(reply),
	}).Info([]string{
		"Success",           //200-299
		"Success",           //300-399
		"Temporary failure", //400-499
		"Permanent failure", //500-599
	}[(reply.Result/100)-2])
	return
}
