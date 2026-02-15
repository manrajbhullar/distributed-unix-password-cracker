package main

/*
#cgo LDFLAGS: -lcrypt
#include <crypt.h>
#include <stdlib.h>
*/
import "C"

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"crypto/subtle"
	"unsafe"

	"github.com/tredoe/crypt"
	_ "github.com/tredoe/crypt/md5_crypt"
	_ "github.com/tredoe/crypt/sha256_crypt"
	_ "github.com/tredoe/crypt/sha512_crypt"

	xbcrypt "golang.org/x/crypto/bcrypt"
)


func verifyYescrypt(candidate, fullHash string) bool {
	cCand := C.CString(candidate)
	cSetting := C.CString(fullHash)
	defer C.free(unsafe.Pointer(cCand))
	defer C.free(unsafe.Pointer(cSetting))

	var data C.struct_crypt_data
	data.initialized = 0

	out := C.crypt_r(cCand, cSetting, &data)
	if out == nil {
		return false
	}

	got := C.GoString(out)
	return subtle.ConstantTimeCompare([]byte(got), []byte(fullHash)) == 1
}


//
// ---------------- messaging (same as messaging.py) ----------------
// 4-byte big-endian length prefix + compact JSON
//

func sendMsg(conn net.Conn, obj any) error {
	payload, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))

	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err = conn.Write(payload)
	return err
}

func recvExact(conn net.Conn, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("ERROR: Connection closed while reading data")
		}
		return nil, err
	}
	return buf, nil
}

func recvMsg(conn net.Conn) (map[string]any, error) {
	hdr, err := recvExact(conn, 4)
	if err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr)
	payload, err := recvExact(conn, int(n))
	if err != nil {
		return nil, err
	}

	var out map[string]any
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func recvWithTimeout(conn net.Conn, seconds float64) (map[string]any, error) {
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(seconds * float64(time.Second))))
	msg, err := recvMsg(conn)
	_ = conn.SetReadDeadline(time.Time{})
	return msg, err
}

//
// ---------------- FSM types ----------------
//

type State int

const (
	StateParseArgs State = iota
	StateHandleArgs
	StateConnect
	StateRegister
	StateWaitJob
	StateCrack
	StateSendResult
	StateCleanup
	StateError
)

type Settings struct {
	ControllerHost string
	ControllerPort int
}

type Context struct {
	Settings Settings

	ExitMessage string
	Controller  net.Conn
	WorkerID    string

	JobData           map[string]any
	SendResultLatency *float64

	InterruptedCrack bool
	CurrentState     State
}

type Handler func(*Context) State

//
// ---------------- helpers ----------------
//

func newUUIDHexLikePython() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func strFromAny(v any) string {
	s, _ := v.(string)
	return s
}

func intFromAny(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	default:
		return 0
	}
}

//
// ---------------- states ----------------
//

func parse_arguments(ctx *Context) State {
	fs := flag.NewFlagSet("Distributed UNIX Password Cracker Worker", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var controller string
	var port int

	// Short flags only
	fs.StringVar(&controller, "c", "", "Controller host or IP")
	fs.IntVar(&port, "p", 0, "Controller port")

	if err := fs.Parse(os.Args[1:]); err != nil {
		ctx.ExitMessage = err.Error()
		return StateError
	}

	if controller == "" || port == 0 {
		fmt.Fprintln(os.Stderr, "Missing required flags: -c -p")
		fs.Usage()
		ctx.ExitMessage = "Missing required flags"
		return StateError
	}

	ctx.Settings.ControllerHost = controller
	ctx.Settings.ControllerPort = port
	return StateHandleArgs
}

func handle_arguments(ctx *Context) State {
	port := ctx.Settings.ControllerPort
	if !(1024 <= port && port <= 65535) {
		ctx.ExitMessage = "ERROR: Port must be between 1024 and 65535"
		return StateError
	}

	ctx.WorkerID = newUUIDHexLikePython()
	fmt.Printf("\nWORKER ID: %s\n", ctx.WorkerID)

	return StateConnect
}

func connect(ctx *Context) State {
	host := ctx.Settings.ControllerHost
	port := ctx.Settings.ControllerPort

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		ctx.ExitMessage = fmt.Sprintf("ERROR: Connection attempt failed. %v", err)
		return StateError
	}

	ctx.Controller = conn
	fmt.Printf("\nCONNECTED TO CONTROLLER: %s:%d\n", host, port)
	return StateRegister
}

func register(ctx *Context) State {
	if ctx.Controller == nil {
		ctx.ExitMessage = "ERROR: No controller socket"
		return StateError
	}

	fmt.Println("  Sending registration request...")

	register_msg := map[string]any{
		"type":      "register",
		"worker_id": ctx.WorkerID,
	}
	if err := sendMsg(ctx.Controller, register_msg); err != nil {
		ctx.ExitMessage = fmt.Sprintf("ERROR: Registration failed. %v", err)
		return StateError
	}

	fmt.Println("  Waiting for approval from controller...")
	resp, err := recvWithTimeout(ctx.Controller, 5.0)
	if err != nil {
		ctx.ExitMessage = fmt.Sprintf("ERROR: Registration failed. %v", err)
		return StateError
	}

	if strFromAny(resp["type"]) != "registration_ok" {
		ctx.ExitMessage = "ERROR: Registration rejected"
		return StateError
	}

	fmt.Println("  Worker registered successfully")
	return StateWaitJob
}

func receive_job(ctx *Context) State {
	fmt.Printf("\nWORKER READY\n")
	fmt.Println("  Waiting for job from controller...")

	job, err := recvMsg(ctx.Controller)
	if err != nil {
		ctx.ExitMessage = fmt.Sprintf("ERROR: Receiving job failed. %v", err)
		return StateError
	}

	ack := map[string]any{
		"type":   "job_ack",
		"job_id": job["job_id"],
	}
	_ = sendMsg(ctx.Controller, ack)

	if strFromAny(job["type"]) != "job" {
		ctx.ExitMessage = fmt.Sprintf("ERROR: Unexpected message type: %v", job["type"])
		return StateError
	}

	ctx.JobData = job
	fmt.Printf("  Job #%d received from controller -> (User: %s, Alg_ID: %s)\n",
		intFromAny(job["job_id"]),
		strFromAny(job["username"]),
		strFromAny(job["alg_id"]),
	)

	return StateCrack
}

func crack(ctx *Context) State {
	job := ctx.JobData

	target_hash := strFromAny(job["hash_full"])
	charset := strFromAny(job["charset"])
	alg_id := strFromAny(job["alg_id"])

	found_password := ""
	attempts := 0
	status_message := "Search Exhausted"

	fmt.Printf("\nJOB #%d STARTED\n", intFromAny(job["job_id"]))
	fmt.Printf("  Cracking password...\n")

	start_time := time.Now()

	for length := 1; ; length++ {
		fmt.Printf("  Testing passwords of length: %d...\n", length)

		base := len(charset)
		idx := make([]int, length)

		for {
			if ctx.InterruptedCrack {
				status_message = "Manually Interrupted"
				goto done
			}

			attempts++

			var sb strings.Builder
			for i := 0; i < length; i++ {
				sb.WriteByte(charset[idx[i]])
			}
			candidate := sb.String()

			match := false

			if alg_id == "1" {
				c := crypt.MD5.New()
				err := c.Verify(target_hash, []byte(candidate))
				match = (err == nil)

			} else if alg_id == "5" {
				c := crypt.SHA256.New()
				err := c.Verify(target_hash, []byte(candidate))
				match = (err == nil)

			} else if alg_id == "6" {
				c := crypt.SHA512.New()
				err := c.Verify(target_hash, []byte(candidate))
				match = (err == nil)

			} else if alg_id == "2b" || alg_id == "2y" || alg_id == "2a" {
				err := xbcrypt.CompareHashAndPassword([]byte(target_hash), []byte(candidate))
				match = (err == nil)


			} else if alg_id == "y" {
				match = verifyYescrypt(candidate, target_hash)
			}

			if match {
				found_password = candidate
				goto done
			}

			pos := length - 1
			for pos >= 0 {
				idx[pos]++
				if idx[pos] < base {
					break
				}
				idx[pos] = 0
				pos--
			}
			if pos < 0 {
				break
			}
		}
	}

done:
	end_time := time.Now()

	result_status := status_message
	if found_password != "" {
		result_status = "Success"
	}

	job["result"] = map[string]any{
		"found":        found_password != "",
		"password":     func() string { if found_password != "" { return found_password }; return "N/A" }(),
		"compute_time": end_time.Sub(start_time).Seconds(),
		"attempts":     attempts,
		"status":       result_status,
	}

	fmt.Printf("  Cracking process has completed\n")
	return StateSendResult
}

func send_result(ctx *Context) State {
	result := ctx.JobData["result"].(map[string]any)

	result_msg := map[string]any{
		"type":         "result",
		"job_id":       ctx.JobData["job_id"],
		"found":        result["found"],
		"password":     result["password"],
		"attempts":     result["attempts"],
		"compute_time": result["compute_time"],
		"status":       result["status"],
	}

	send_result_start := time.Now()
	_ = sendMsg(ctx.Controller, result_msg)

	ack, _ := recvMsg(ctx.Controller)

	if strFromAny(ack["type"]) != "result_ack" {
		ctx.ExitMessage = fmt.Sprintf("ERROR: Expected result_ack, got: %v", ack)
		return StateError
	}

	lat := time.Since(send_result_start).Seconds()
	ctx.SendResultLatency = &lat

	_ = sendMsg(ctx.Controller, map[string]any{
		"result_return_latency": lat,
	})

	fmt.Printf("\nRESULT SENT TO CONTROLLER\n")
	fmt.Printf("  Result Return Latency: %.2f milliseconds (W -> C)\n", lat*1000)
	fmt.Printf("\nJOB #1 COMPLETE\n")
	return StateCleanup
}

func error_state(ctx *Context) State {
	fmt.Printf("\n%s\n", ctx.ExitMessage)
	return StateCleanup
}

func cleanup(ctx *Context) State {
	if ctx.Controller != nil {
		_ = ctx.Controller.Close()
	}
	fmt.Printf("\nEXITING PROGRAM\n")
	os.Exit(0)
	return StateCleanup
}

//
// ---------------- main ----------------
//

func main() {
	fmt.Println("--- WORKER ---")

	ctx := &Context{}

	handlers := map[State]Handler{
		StateParseArgs:  parse_arguments,
		StateHandleArgs: handle_arguments,
		StateConnect:    connect,
		StateRegister:   register,
		StateWaitJob:    receive_job,
		StateCrack:      crack,
		StateSendResult: send_result,
		StateError:      error_state,
		StateCleanup:    cleanup,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		if ctx.CurrentState == StateCrack {
			ctx.InterruptedCrack = true
			return
		}
		handlers[StateCleanup](ctx)
	}()

	state := StateParseArgs
	for {
		ctx.CurrentState = state
		state = handlers[state](ctx)
	}
}
