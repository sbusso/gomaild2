package starttls

import (
	"crypto/tls"
	"fmt"
	log "github.com/sirupsen/logrus"
	config "github.com/spf13/viper"
	. "github.com/trapped/gomaild2/smtp/structs"
	. "github.com/trapped/gomaild2/structs"
)

func initTLS() {
	WaitConfig("config.loaded")
	if config.GetBool("tls.enabled") {
		log.Info("Enabled TLS")
		Extensions = append(Extensions, "STARTTLS")
	}
}

func init() {
	go initTLS()
}

func getCerts() ([]tls.Certificate, error) {
	if !config.GetBool("tls.enabled") ||
		config.GetString("tls.certificate") == "" ||
		config.GetString("tls.key") == "" {
		return []tls.Certificate{}, fmt.Errorf("extension disabled")
	}

	cert, err := tls.LoadX509KeyPair(config.GetString("tls.certificate"), config.GetString("tls.key"))
	if err != nil {
		log.Error("Couldn't load TLS certificate: ", err)
		return []tls.Certificate{}, fmt.Errorf("crypto error")
	}

	return []tls.Certificate{cert}, nil
}

func getConfig() (*tls.Config, error) {
	certs, err := getCerts()
	if err != nil {
		return &tls.Config{}, err
	}
	return &tls.Config{
		Certificates: certs,
	}, nil
}

func Process(c *Client, cmd Command) Reply {
	conf, err := getConfig()
	if err != nil {
		switch err.Error() {
		case "extension disabled":
			return Reply{
				Result:  CommandNotImplemented,
				Message: err.Error(),
			}
		case "crypto error":
			return Reply{
				Result:  LocalError,
				Message: err.Error(),
			}
		default:
			return Reply{
				Result:  LocalError,
				Message: "unknown processing error",
			}
		}
	}

	c.Send(Reply{
		Result:  Ready,
		Message: "ready to start TLS",
	})

	conn := tls.Server(c.Conn, conf)
	err = conn.Handshake()
	if err != nil {
		log.WithFields(log.Fields{
			"id":  c.ID,
			"err": err,
		}).Error("TLS handshake failed")
		c.State = Disconnected
		return Reply{
			Result:  LocalError,
			Message: "TLS handshake failed",
		}
	}
	c.Conn = conn

	log.WithField("id", c.ID).Info("Switched to TLS")

	c.ResetData()
	c.Set("secure", true)
	c.State = Connected
	c.MakeReader()

	return Reply{
		Result: Ignore,
	}
}
