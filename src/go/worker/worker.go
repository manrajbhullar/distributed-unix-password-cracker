package main

/*
#cgo LDFLAGS: -lcrypt
#include <crypt.h>
#include <stdlib.h>
*/
import "C"

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/tredoe/crypt"
	_ "github.com/tredoe/crypt/md5_crypt"
	_ "github.com/tredoe/crypt/sha256_crypt"
	_ "github.com/tredoe/crypt/sha512_crypt"

	xbcrypt "golang.org/x/crypto/bcrypt"
)

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
	Threads        int
}

type Context struct {
	Settings Settings

	ExitMessage string
	Controller  net.Conn
	sendMu      sync.Mutex
	WorkerID    string

	JobData           map[string]any
	SendResultLatency *float64

	InterruptedCrack int32
	CurrentState     int32
}

type Handler func(*Context) State

func parse_arguments(ctx *Context) State {
	fs := flag.NewFlagSet("Distributed UNIX Password Cracker Worker", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var controller string
	var port int
	var threads int

	fs.StringVar(&controller, "c", "", "Controller host or IP")
	fs.IntVar(&port, "p", 0, "Controller port")
	fs.IntVar(&threads, "t", 1, "Number of threads")

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
	ctx.Settings.Threads = threads

	return StateHandleArgs
}

func handle_arguments(ctx *Context) State {
	port := ctx.Settings.ControllerPort
	if !(1024 <= port && port <= 65535) {
		ctx.ExitMessage = "ERROR: Port must be between 1024 and 65535"
		return StateError
	}

	if ctx.Settings.Threads <= 0 {
		ctx.ExitMessage = "ERROR: Threads must be greater than 0"
		return StateError
	}

	ctx.WorkerID = newUUID()
	fmt.Printf("\nWORKER ID: %s\n", ctx.WorkerID)
	fmt.Printf("THREADS: %d\n", ctx.Settings.Threads)

	return StateConnect
}

func connect(ctx *Context) State {
	host := ctx.Settings.ControllerHost
	port := ctx.Settings.ControllerPort

	//conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	conn, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
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
	//time.Sleep(10 * time.Second) // Test HB Protocol

	job := ctx.JobData
	threads := ctx.Settings.Threads

	targetHash := strFromAny(job["hash_full"])
	charset := strFromAny(job["charset"])
	alg_id := strFromAny(job["alg_id"])

	hbInterval := intFromAny(job["hb_interval"])
	hbDur := time.Duration(hbInterval) * time.Second

	fmt.Printf("\nJOB #%d STARTED\n", intFromAny(job["job_id"]))
	fmt.Printf("  Cracking password with %d threads...\n", threads)

	startTime := time.Now()

	jobs := make(chan string, 1<<12)
	var foundFlag int32 = 0
	var totalAttempts int64 = 0
	var wg sync.WaitGroup
	var foundMu sync.Mutex
	var foundPassword string
	statusMessage := "Search Exhausted"

	// Handle manual interruption
	go func() {
		for {
			if atomic.LoadInt32(&ctx.InterruptedCrack) == 1 {
				atomic.StoreInt32(&foundFlag, 1)
				foundMu.Lock()
				statusMessage = "Manually Interrupted"
				foundMu.Unlock()
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	// Handles heartbeats
	hbDone := make(chan struct{})
	var hbWG sync.WaitGroup
	hbWG.Add(1)
	go func() {
		defer hbWG.Done()
		var lastReported int64 = 0
		lastTime := time.Now()
		ticker := time.NewTicker(hbDur)
		defer ticker.Stop()
		for {
			select {
			case <-hbDone:
				return
			case <-ticker.C:
				total := atomic.LoadInt64(&totalAttempts)
				delta := total - lastReported
				now := time.Now()
				elapsed := now.Sub(lastTime).Seconds()
				rate := 0.0
				if elapsed > 0 {
					rate = float64(delta) / elapsed
				}
				timestamp := time.Now().Format("15:04:05")
				hb := map[string]any{
					"type":           "heartbeat_resp",
					"delta_tested":   delta,
					"total_tested":   total,
					"threads_active": ctx.Settings.Threads,
					"current_rate":   rate,
					"timestamp":      timestamp,
				}
				ctx.sendMu.Lock()
				err := sendMsg(ctx.Controller, hb)
				ctx.sendMu.Unlock()
				if err != nil {
					fmt.Printf("  Connection to controller lost. Continuing cracking...\n")
					return
				}
				lastReported = total
				lastTime = now
				fmt.Printf("  Sent heartbeat response (%s)\n", timestamp)
			}
		}
	}()

	// Candidate generator
	generator := func() {
		defer close(jobs)
		base := len(charset)
		if base == 0 {
			return
		}
		for length := 1; ; length++ {
			fmt.Printf("  Testing passwords of length: %d...\n", length)
			idx := make([]int, length)
			for {
				// Stop if found or interrupted
				if atomic.LoadInt32(&foundFlag) != 0 {
					return
				}
				var sb strings.Builder
				for i := 0; i < length; i++ {
					sb.WriteByte(charset[idx[i]])
				}
				candidate := sb.String()
				// Send candidate
				select {
				case jobs <- candidate:
				default:
					select {
					case jobs <- candidate:
					case <-time.After(10 * time.Millisecond):
						if atomic.LoadInt32(&foundFlag) != 0 {
							return
						}
						jobs <- candidate
					}
				}
				// Update position
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
					// Exhausted this length
					break
				}
			}
		}
	}

	// Verifies according to algorithm type
	verifyCandidate := func(candidate string) bool {
		switch alg_id {
		case "1":
			c := crypt.MD5.New()
			return c.Verify(targetHash, []byte(candidate)) == nil
		case "5":
			c := crypt.SHA256.New()
			return c.Verify(targetHash, []byte(candidate)) == nil
		case "6":
			c := crypt.SHA512.New()
			return c.Verify(targetHash, []byte(candidate)) == nil
		case "2b", "2y", "2a":
			if err := xbcrypt.CompareHashAndPassword([]byte(targetHash), []byte(candidate)); err == nil {
				return true
			}
			return false
		case "y":
			return verifyYescrypt(candidate, targetHash)
		default:
			c := crypt.SHA256.New()
			return c.Verify(targetHash, []byte(candidate)) == nil
		}
	}

	// Consumes candidates and checks if there is a match
	worker := func(id int) {
		_ = id
		defer wg.Done()
		localAttempts := 0
		for candidate := range jobs {
			// Quit if found or interrupted
			if atomic.LoadInt32(&foundFlag) != 0 {
				return
			}
			// Count attempts
			localAttempts++
			atomic.AddInt64(&totalAttempts, 1)
			// Check the password and declare if found
			if verifyCandidate(candidate) {
				if atomic.CompareAndSwapInt32(&foundFlag, 0, 1) {
					foundMu.Lock()
					foundPassword = candidate
					foundMu.Unlock()
				}
				return
			}
			// Exit if another worker found it
			if atomic.LoadInt32(&foundFlag) != 0 {
				return
			}
		}
	}

	runtime.GOMAXPROCS(threads) // Limit Go runtime to the requested amount OS threads
	go generator()              // Start generator
	// Spawn worker threads
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go worker(i)
	}
	wg.Wait()     // Wait for workers to finish
	close(hbDone) // Stop heartbeats
	hbWG.Wait()   // Wait for heartbeat routine to exit

	endTime := time.Now() // End cracking timer

	// Final status
	finalFound := ""
	foundMu.Lock()
	finalFound = foundPassword
	if finalFound != "" {
		statusMessage = "Success"
	}
	final_status := statusMessage
	foundMu.Unlock()

	job["result"] = map[string]any{
		"found": finalFound != "",
		"password": func() string {
			if finalFound != "" {
				return finalFound
			}
			return "N/A"
		}(),
		"compute_time": endTime.Sub(startTime).Seconds(),
		"attempts":     int(atomic.LoadInt64(&totalAttempts)),
		"status":       final_status,
	}

	fmt.Printf("  Cracking process has completed after %d attempts\n", atomic.LoadInt64(&totalAttempts))

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
	ctx.sendMu.Lock()
	_ = sendMsg(ctx.Controller, result_msg)
	ctx.sendMu.Unlock()

	ack, err := recvMsg(ctx.Controller)
	if err != nil {
		ctx.ExitMessage = "ERROR: Failed to send results to controller"
		return StateError
	}

	if strFromAny(ack["type"]) != "result_ack" {
		ctx.ExitMessage = fmt.Sprintf("ERROR: Expected result_ack, got: %v", ack)
		return StateError
	}

	lat := time.Since(send_result_start).Seconds()
	ctx.SendResultLatency = &lat

	ctx.sendMu.Lock()
	_ = sendMsg(ctx.Controller, map[string]any{
		"result_return_latency": lat,
	})
	ctx.sendMu.Unlock()

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
		if atomic.LoadInt32(&ctx.CurrentState) == int32(StateCrack) {
			atomic.StoreInt32(&ctx.InterruptedCrack, 1)
			return
		}
		handlers[StateCleanup](ctx)
	}()

	state := StateParseArgs
	for {
		atomic.StoreInt32(&ctx.CurrentState, int32(state))
		state = handlers[state](ctx)
	}
}

// ---------- Messaging ----------

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

// ---------- Helpers ----------

func newUUID() string {
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
