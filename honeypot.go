package main

import (
	"code.google.com/p/go.crypto/ssh"
	"code.google.com/p/go.crypto/ssh/terminal"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/pmylund/go-cache"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var c = cache.New(10*time.Minute, 300*time.Second)

type Configuration struct {
	UserId string
	Token  string
}

var conf = &Configuration{}

type Attacker struct {
	addr     string
	username string
	password string
}

func (a *Attacker) String() string {
	if len(a.username) > 0 {
		return fmt.Sprintf("%s - %s:%s", a.addr, a.username, a.password)
	}
	return fmt.Sprintf("%s - SSH Key Attempt", a.addr)
}

func ipAddrFromRemoteAddr(s string) string {
	idx := strings.LastIndex(s, ":")
	if idx == -1 {
		return s
	}
	return s[:idx]
}

func newAttacker(conn *ssh.ServerConn, username string, password string) *Attacker {
	addr := conn.RemoteAddr().String()
	addr = ipAddrFromRemoteAddr(addr)
	return &Attacker{addr, username, password}
}

func notify(attacker *Attacker) {
	log.Println("Attempt", attacker.String())
	_, found := c.Get(attacker.addr)
	if !found {
		go pushNotify(attacker)
		c.Set(attacker.addr, 1, 0)
	}
}

func pushNotify(attacker *Attacker) {
	if conf.Token == "" || conf.UserId == "" {
		return
	}
	// Fails on Docker. Not worth fixing at the moment due to low risk
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.PostForm("https://api.pushover.net/1/messages.json",
		url.Values{"token": {conf.Token}, "user": {conf.UserId}, "message": {attacker.String()}})
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Println(resp.Status)
}

func main() {
	// Config parse
	file, err := os.Open("./conf.json")
	if err != nil {
		log.Fatal("Error opening config file")
	}
	decoder := json.NewDecoder(file)
	decoder.Decode(&conf)
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PasswordCallback: func(conn *ssh.ServerConn, user, pass string) bool {
			notify(newAttacker(conn, user, pass))
			return false
		},
	}

	pemBytes, err := ioutil.ReadFile("rsa.key")
	if err != nil {
		log.Fatal("Failed to load private key:", err)
	}
	if err = config.SetRSAPrivateKey(pemBytes); err != nil {
		log.Fatal("Failed to parse private key:", err)
	}

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	conn, err := ssh.Listen("tcp", "0.0.0.0:2022", config)
	if err != nil {
		log.Fatal("failed to listen for connection")
	}
	for {
		// A ServerConn multiplexes several channels, which must
		// themselves be Accepted.
		log.Println("accept")
		sConn, err := conn.Accept()
		attacker := newAttacker(sConn, "", "")
		if err != nil {
			notify(attacker)
			log.Println("failed to accept incoming connection")
			continue
		}
		if err := sConn.Handshake(); err != nil {
			notify(attacker)
			log.Println("failed to handshake")
			continue
		}
		go handleServerConn(sConn)
	}
}

func handleServerConn(sConn *ssh.ServerConn) {
	defer sConn.Close()
	for {
		// Accept reads from the connection, demultiplexes packets
		// to their corresponding channels and returns when a new
		// channel request is seen. Some goroutine must always be
		// calling Accept; otherwise no messages will be forwarded
		// to the channels.
		ch, err := sConn.Accept()
		if err == io.EOF {
			return
		}
		if err != nil {
			log.Println("handleServerConn Accept:", err)
			break
		}
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if ch.ChannelType() != "session" {
			ch.Reject(ssh.UnknownChannelType, "unknown channel type")
			break
		}
		go handleChannel(ch)
	}
}

func handleChannel(ch ssh.Channel) {
	term := terminal.NewTerminal(ch, "> ")
	serverTerm := &ssh.ServerTerminal{
		Term:    term,
		Channel: ch,
	}
	ch.Accept()
	defer ch.Close()
	for {
		line, err := serverTerm.ReadLine()
		if err == io.EOF {
			return
		}
		if err != nil {
			log.Println("handleChannel readLine err:", err)
			continue
		}
		fmt.Println(line)
	}
}
