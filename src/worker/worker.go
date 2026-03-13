package main

/*
#cgo LDFLAGS: -lcrypt
#include <crypt.h>
#include <stdlib.h>
*/
import "C"

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
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
	StateRequestJob
	StateCrack
	StateSendJobResult
	StateStopWorker
	StateError
	StateCleanup
)

type Settings struct {
	ControllerHost string
	ControllerPort int
	Threads        int
	ThreadsRaw     string
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
	ForceStop        int32
	CurrentState     int32

	TotalAttempts int64
	IncomingMsgs  chan map[string]any
}

type Handler func(*Context) State

func parse_arguments(ctx *Context) State {
	fs := flag.NewFlagSet("Distributed UNIX Password Cracker Worker", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var controller string
	var port int
	var threadsStr string

	fs.StringVar(&controller, "c", "", "Controller host or IP")
	fs.IntVar(&port, "p", 0, "Controller port")
	fs.StringVar(&threadsStr, "t", "1", "Number of threads (integer or \"max\" for NumCPU-1)")

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
	ctx.Settings.ThreadsRaw = threadsStr

	return StateHandleArgs
}

func handle_arguments(ctx *Context) State {
	port := ctx.Settings.ControllerPort
	if !(1024 <= port && port <= 65535) {
		ctx.ExitMessage = "ERROR: Port must be between 1024 and 65535"
		return StateError
	}

	if ctx.Settings.ThreadsRaw == "max" {
		ctx.Settings.Threads = runtime.NumCPU() - 1
		if ctx.Settings.Threads < 1 {
			ctx.Settings.Threads = 1
		}
	} else {
		n, err := strconv.Atoi(ctx.Settings.ThreadsRaw)
		if err != nil || n <= 0 {
			ctx.ExitMessage = fmt.Sprintf("ERROR: Invalid value for -t: %q (must be a positive integer or \"max\")", ctx.Settings.ThreadsRaw)
			return StateError
		}
		ctx.Settings.Threads = n
	}

	fmt.Printf("THREADS: %d\n", ctx.Settings.Threads)

	return StateConnect
}

func connect(ctx *Context) State {
	host := ctx.Settings.ControllerHost
	port := ctx.Settings.ControllerPort

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
		"type": "register",
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

	ctx.WorkerID = strFromAny(resp["worker_id"])
	fmt.Printf("  Worker registered successfully (WorkerID: %s, User: %s, Alg_ID: %s)\n",
		ctx.WorkerID,
		strFromAny(resp["username"]),
		strFromAny(resp["alg_id"]),
	)
	//time.Sleep(time.Second * 5)
	startMessageReader(ctx)
	return StateRequestJob
}

func request_job(ctx *Context) State {
	fmt.Printf("\nREADY FOR JOB\n")
	//time.Sleep(10 * time.Second)
	fmt.Println("  Requesting job from controller...")

	req := map[string]any{
		"type":      "job_request",
		"worker_id": ctx.WorkerID,
	}
	if err := sendMsg(ctx.Controller, req); err != nil {
		ctx.ExitMessage = fmt.Sprintf("ERROR: Job request failed. %v", err)
		return StateError
	}

	job, ok := <-ctx.IncomingMsgs
	if !ok {
		ctx.ExitMessage = "ERROR: Connection to controller lost"
		return StateError
	}

	if strFromAny(job["type"]) == "stop" {
		return StateStopWorker
	}

	if strFromAny(job["type"]) == "force_stop" {
		fmt.Printf("\nPASSWORD FOUND\n")
		fmt.Printf("  No active job\n")
		ctx.sendMu.Lock()
		_ = sendMsg(ctx.Controller, map[string]any{
			"type":     "force_stop_ack",
			"attempts": 0,
		})
		ctx.sendMu.Unlock()
		return StateCleanup
	}

	ack := map[string]any{
		"type":   "job_ack",
		"job_id": job["job_id"],
	}
	ctx.sendMu.Lock()
	_ = sendMsg(ctx.Controller, ack)
	ctx.sendMu.Unlock()

	if strFromAny(job["type"]) != "job" {
		ctx.ExitMessage = fmt.Sprintf("ERROR: Unexpected message type: %v", job["type"])
		return StateError
	}

	ctx.JobData = job
	fmt.Printf("  Job #%d received from controller -> (Chunk: %d to %d)\n",
		intFromAny(job["job_id"]),
		int64FromAny(job["chunk_start"]),
		int64FromAny(job["chunk_start"])+int64(intFromAny(job["chunk_size"])),
	)

	return StateCrack
}

func startMessageReader(ctx *Context) {
	ctx.IncomingMsgs = make(chan map[string]any, 16)
	go func() {
		var lastHBAttempts int64
		lastHBTime := time.Now()
		for {
			msg, err := recvMsg(ctx.Controller)
			if err != nil {
				close(ctx.IncomingMsgs)
				return
			}
			if strFromAny(msg["type"]) == "heartbeat_req" {
				total := atomic.LoadInt64(&ctx.TotalAttempts)
				delta := total - lastHBAttempts
				now := time.Now()
				elapsed := now.Sub(lastHBTime).Seconds()
				rate := 0.0
				if elapsed > 0 {
					rate = float64(delta) / elapsed
				}
				lastHBAttempts = total
				lastHBTime = now
				resp := map[string]any{
					"type":           "heartbeat_resp",
					"delta_tested":   delta,
					"total_tested":   total,
					"threads_active": ctx.Settings.Threads,
					"current_rate":   rate,
					"timestamp":      now.Format("15:04:05"),
				}
				ctx.sendMu.Lock()
				_ = sendMsg(ctx.Controller, resp)
				ctx.sendMu.Unlock()
				fmt.Printf("  Sent heartbeat response (%s)\n", now.Format("15:04:05"))
				continue
			}
			ctx.IncomingMsgs <- msg
		}
	}()
}

func crack(ctx *Context) State {
	job := ctx.JobData
	threads := ctx.Settings.Threads

	targetHash := strFromAny(job["hash_full"])
	charset := strFromAny(job["charset"])
	alg_id := strFromAny(job["alg_id"])

	chunkStart := int64FromAny(job["chunk_start"])
	chunkEnd := chunkStart + int64(intFromAny(job["chunk_size"]))

	fmt.Printf("\nJOB #%d STARTED\n", intFromAny(job["job_id"]))
	fmt.Printf("  Cracking passwords %d to %d in this chunk with %d threads...\n", chunkStart, chunkEnd, threads)

	startTime := time.Now()

	jobs := make(chan string, 1<<12)
	var foundFlag int32 = 0
	var jobAttempts int64 = 0
	var wg sync.WaitGroup
	var foundMu sync.Mutex
	var foundPassword string
	statusMessage := "Search Exhausted"

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

	fsStopCh := make(chan struct{})
	var fsWG sync.WaitGroup
	fsWG.Add(1)
	go func() {
		defer fsWG.Done()
		for {
			select {
			case <-fsStopCh:
				return
			case msg, ok := <-ctx.IncomingMsgs:
				if !ok {
					return
				}
				if strFromAny(msg["type"]) == "force_stop" {
					atomic.StoreInt32(&ctx.ForceStop, 1)
					atomic.StoreInt32(&foundFlag, 1)
				}
				return
			}
		}
	}()

	generator := func() {
		defer close(jobs)
		for i := chunkStart; i < chunkEnd; i++ {
			if atomic.LoadInt32(&foundFlag) != 0 {
				return
			}
			candidate := indexToCandidate(i, charset)
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
		}
	}

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

	worker := func(id int) {
		_ = id
		defer wg.Done()
		localAttempts := 0
		for candidate := range jobs {
			if atomic.LoadInt32(&foundFlag) != 0 {
				return
			}
			localAttempts++
			atomic.AddInt64(&jobAttempts, 1)
			atomic.AddInt64(&ctx.TotalAttempts, 1)
			if verifyCandidate(candidate) {
				if atomic.CompareAndSwapInt32(&foundFlag, 0, 1) {
					foundMu.Lock()
					foundPassword = candidate
					foundMu.Unlock()
				}
				return
			}
			if atomic.LoadInt32(&foundFlag) != 0 {
				return
			}
		}
	}

	runtime.GOMAXPROCS(threads)
	go generator()
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go worker(i)
	}
	wg.Wait()
	close(fsStopCh)
	fsWG.Wait()

	endTime := time.Now()

	finalFound := ""
	foundMu.Lock()
	finalFound = foundPassword
	if finalFound != "" {
		statusMessage = "Success"
	}
	final_status := statusMessage
	foundMu.Unlock()

	computeTime := endTime.Sub(startTime).Seconds()
	attempts := int(atomic.LoadInt64(&jobAttempts))
	hps := 0.0
	if computeTime > 0 {
		hps = float64(attempts) / computeTime
	}

	job["result"] = map[string]any{
		"found": finalFound != "",
		"password": func() string {
			if finalFound != "" {
				return finalFound
			}
			return "N/A"
		}(),
		"compute_time": computeTime,
		"attempts":     attempts,
		"hps":          hps,
		"status":       final_status,
	}
	fmt.Printf("  Cracking has completed for this chunk after %d attempts\n", atomic.LoadInt64(&jobAttempts))

	if atomic.LoadInt32(&ctx.ForceStop) == 1 {
		fmt.Printf("\nPASSWORD FOUND\n")
		fmt.Printf("  Stopped %d password attempts into Job #%d\n", atomic.LoadInt64(&jobAttempts), intFromAny(job["job_id"]))
		ctx.sendMu.Lock()
		_ = sendMsg(ctx.Controller, map[string]any{
			"type":     "force_stop_ack",
			"attempts": int(atomic.LoadInt64(&jobAttempts)),
		})
		ctx.sendMu.Unlock()
		return StateCleanup
	}

	return StateSendJobResult
}

func send_job_result(ctx *Context) State {
	result := ctx.JobData["result"].(map[string]any)
	found, _ := result["found"].(bool)

	result_msg := map[string]any{
		"type":         "result",
		"job_id":       ctx.JobData["job_id"],
		"found":        result["found"],
		"password":     result["password"],
		"attempts":     result["attempts"],
		"compute_time": result["compute_time"],
		"hps":          result["hps"],
		"status":       result["status"],
	}

	send_result_start := time.Now()
	ctx.sendMu.Lock()
	err := sendMsg(ctx.Controller, result_msg)
	ctx.sendMu.Unlock()
	if err != nil {
		return StateCleanup
	}

	for {
		msg, ok := <-ctx.IncomingMsgs
		if !ok {
			return StateCleanup
		}
		if strFromAny(msg["type"]) == "force_stop" {
			atomic.StoreInt32(&ctx.ForceStop, 1)
			return StateCleanup
		}
		if strFromAny(msg["type"]) == "result_ack" {
			break
		}
		return StateCleanup
	}

	lat := time.Since(send_result_start).Seconds()
	ctx.SendResultLatency = &lat

	ctx.sendMu.Lock()
	_ = sendMsg(ctx.Controller, map[string]any{
		"result_return_latency": lat,
	})
	ctx.sendMu.Unlock()

	fmt.Printf("\nJOB #%d RESULT SENT\n", intFromAny(ctx.JobData["job_id"]))
	fmt.Printf("  Status: %s\n", strFromAny(result["status"]))
	if found {
		fmt.Printf("  Password: %s\n", strFromAny(result["password"]))
	}
	fmt.Printf("  Result Return Latency: %.2f milliseconds (W -> C)\n", lat*1000)

	if found || atomic.LoadInt32(&ctx.InterruptedCrack) == 1 {
		ctx.sendMu.Lock()
		_ = sendMsg(ctx.Controller, map[string]any{
			"type":      "disconnect",
			"worker_id": ctx.WorkerID,
		})
		ctx.sendMu.Unlock()
		return StateCleanup
	}

	return StateRequestJob
}

func stop_worker(ctx *Context) State {
	fmt.Printf("\nSTOP RECEIVED (WorkerID: %s) - password found by another worker\n", ctx.WorkerID)
	ctx.sendMu.Lock()
	_ = sendMsg(ctx.Controller, map[string]any{
		"type":      "disconnect",
		"worker_id": ctx.WorkerID,
	})
	ctx.sendMu.Unlock()
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
		StateParseArgs:     parse_arguments,
		StateHandleArgs:    handle_arguments,
		StateConnect:       connect,
		StateRegister:      register,
		StateRequestJob:    request_job,
		StateCrack:         crack,
		StateSendJobResult: send_job_result,
		StateStopWorker:    stop_worker,
		StateError:         error_state,
		StateCleanup:       cleanup,
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

func int64FromAny(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	default:
		return 0
	}
}

func indexToCandidate(index int64, charset string) string {
	base := int64(len(charset))
	length := 1
	count := base
	for index >= count {
		index -= count
		length++
		count *= base
	}
	result := make([]byte, length)
	for i := length - 1; i >= 0; i-- {
		result[i] = charset[index%base]
		index /= base
	}
	return string(result)
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
