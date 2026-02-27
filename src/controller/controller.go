package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type State int

const (
	StateParseArgs State = iota
	StateHandleArgs
	StateParseShadow
	StateListen
	StateRegisterWorker
	StateMonitorProgress
	StateDispatchJob
	StateError
	StateCleanup
)

type Settings struct {
	Filename          string
	Username          string
	Port              int
	HeartbeatInterval int
}

type PasswordInfo struct {
	AlgID string
	Salt  string
	Hash  string
	Full  string
}

type WorkerInfo struct {
	Conn   net.Conn
	ID     string
	Addr   string
	JobID  int
	HasJob bool

	RuntimeStart        *time.Time
	DispatchLatency     *float64
	ResultReturnLatency *float64
}

type Context struct {
	Settings    Settings
	ExitMessage string

	PwInfo PasswordInfo

	ServerLn net.Listener

	Workers      map[string]*WorkerInfo
	WorkersMu    sync.Mutex
	NextJobID    int
	NextWorkerID int

	ParseStart *time.Time
	ParseEnd   *time.Time
	ParseTime  *float64
}

type Handler func(*Context) State

func parse_arguments(ctx *Context) State {
	fs := flag.NewFlagSet("Distributed UNIX Password Cracker Controller", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var filename string
	var username string
	var port int
	var heartbeat int

	fs.StringVar(&filename, "f", "", "Name of shadow file")
	fs.StringVar(&username, "u", "", "Username whose password being cracked")
	fs.IntVar(&port, "p", 0, "Port number control server runs on")
	fs.IntVar(&heartbeat, "b", -1, "Heartbeat interval in seconds")

	if err := fs.Parse(os.Args[1:]); err != nil {
		ctx.ExitMessage = err.Error()
		return StateError
	}

	if filename == "" || username == "" || port == 0 || heartbeat == -1 {
		fmt.Fprintln(os.Stderr, "Missing required flags: -f -u -p -b")
		fs.Usage()
		ctx.ExitMessage = "Missing required flags"
		return StateError
	}

	ctx.Settings.Filename = filename
	ctx.Settings.Username = username
	ctx.Settings.Port = port
	ctx.Settings.HeartbeatInterval = heartbeat

	return StateHandleArgs
}

func handle_arguments(ctx *Context) State {
	port := ctx.Settings.Port
	if port < 1024 || port > 65535 {
		ctx.ExitMessage = "ERROR: Port must be between 1024 and 65535"
		return StateError
	}

	heartbeat := ctx.Settings.HeartbeatInterval
	if heartbeat <= 0 {
		ctx.ExitMessage = "ERROR: Heartbeat interval must be greater than 0"
		return StateError
	}

	f, err := os.Open(ctx.Settings.Filename)
	if err != nil {
		if os.IsNotExist(err) {
			ctx.ExitMessage = "ERROR: Shadow file not found"
			return StateError
		}
		if os.IsPermission(err) {
			ctx.ExitMessage = "ERROR: Shadow file not readable"
			return StateError
		}
		ctx.ExitMessage = "ERROR: Shadow file not readable"
		return StateError
	}
	_ = f.Close()

	return StateParseShadow
}

func parse_shadow(ctx *Context) State {
	username := ctx.Settings.Username
	filename := ctx.Settings.Filename

	start := time.Now()
	ctx.ParseStart = &start

	f, err := os.Open(filename)
	if err != nil {
		ctx.ExitMessage = "ERROR: Failed to parse shadow file"
		return StateError
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}

		user := fields[0]
		password := fields[1]

		if user != username {
			continue
		}

		// Unusable hash
		if password == "" || password == "!" || password == "*" || password == "!!" {
			ctx.ExitMessage = fmt.Sprintf("ERROR: User '%s' has no usable hash", username)
			return StateError
		}

		ctx.PwInfo.Full = password

		if !strings.HasPrefix(password, "$") {
			ctx.ExitMessage = "ERROR: User hash failed to tokenize"
			return StateError
		}

		tokens := strings.Split(password, "$")
		if len(tokens) < 4 {
			ctx.ExitMessage = "ERROR: User hash failed to tokenize"
			return StateError
		}

		ctx.PwInfo.AlgID = tokens[1]

		if ctx.PwInfo.AlgID == "1" {
			if len(tokens) < 4 {
				ctx.ExitMessage = "ERROR: User hash failed to tokenize"
				return StateError
			}
			ctx.PwInfo.Salt = tokens[2]
			ctx.PwInfo.Hash = tokens[3]

		} else if ctx.PwInfo.AlgID == "2a" || ctx.PwInfo.AlgID == "2b" || ctx.PwInfo.AlgID == "2x" || ctx.PwInfo.AlgID == "2y" {
			if len(tokens) < 4 {
				ctx.ExitMessage = "ERROR: User hash failed to tokenize"
				return StateError
			}
			combined := tokens[3]
			if len(combined) < 22 {
				ctx.ExitMessage = "ERROR: User hash failed to tokenize"
				return StateError
			}
			ctx.PwInfo.Salt = combined[:22]
			ctx.PwInfo.Hash = combined[22:]

		} else {
			if len(tokens) < 5 {
				ctx.ExitMessage = "ERROR: User hash failed to tokenize"
				return StateError
			}
			ctx.PwInfo.Salt = tokens[3]
			ctx.PwInfo.Hash = tokens[4]
		}

		end := time.Now()
		ctx.ParseEnd = &end
		parseSeconds := end.Sub(start).Seconds()
		ctx.ParseTime = &parseSeconds

		fmt.Printf("\nPARSED SHADOW FILE\n")
		fmt.Printf("  User: %s\n", ctx.Settings.Username)
		fmt.Printf("  Alg_ID: %s\n", ctx.PwInfo.AlgID)
		fmt.Printf("  Salt: %s\n", ctx.PwInfo.Salt)
		fmt.Printf("  Hash: %s\n", ctx.PwInfo.Hash)
		fmt.Printf("  Duration: %.2f milliseconds\n", parseSeconds*1000)

		return StateListen
	}

	if err := sc.Err(); err != nil {
		ctx.ExitMessage = "ERROR: Failed to parse shadow file"
		return StateError
	}

	ctx.ExitMessage = fmt.Sprintf("ERROR: Username '%s' not found in shadow file", username)
	return StateError
}

func listen(ctx *Context) State {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", ctx.Settings.Port))
	if err != nil {
		ctx.ExitMessage = fmt.Sprintf("ERROR: Control server failed to start. %v", err)
		return StateError
	}
	ctx.ServerLn = ln
	fmt.Printf("\nLISTENING ON PORT: %d\n", ctx.Settings.Port)

	// Accept loop — continuously accepts new worker connections
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // Listener closed during cleanup
			}
			go handleWorker(ctx, conn)
		}
	}()

	return StateMonitorProgress
}

// handleWorker manages one worker connection lifecycle.
// Calls register_worker, then loops reading messages and
// calls send_chunk to dispatch jobs.
func handleWorker(ctx *Context, conn net.Conn) {
	addr := conn.RemoteAddr().String()
	fmt.Printf("\nWORKER CONNECTED FROM: %s\n", addr)

	// Register the worker
	worker, err := register_worker(ctx, conn, addr)
	if err != nil {
		fmt.Printf("  ERROR: Worker from %s failed to register. %v\n", addr, err)
		_ = conn.Close()
		return
	}

	shortID := worker.ID

	// Per-worker message loop
	heartbeatSec := ctx.Settings.HeartbeatInterval

	for {
		msg, err := recvMsg(conn)
		if err != nil {
			ctx.WorkersMu.Lock()
			delete(ctx.Workers, worker.ID)
			ctx.WorkersMu.Unlock()
			_ = conn.Close()
			fmt.Printf("\nWORKER DISCONNECTED (WorkerID: %s) - connection lost\n", shortID)
			return
		}

		typ := strFromAny(msg["type"])

		switch typ {
		case "job_request":
			send_chunk(ctx, worker, shortID)

		case "heartbeat_resp":
			delta := floatFromAny(msg["delta_tested"])
			total := floatFromAny(msg["total_tested"])
			threadsActive := intFromAny(msg["threads_active"])
			rate := floatFromAny(msg["current_rate"])

			fmt.Printf("\nHEARTBEAT (WorkerID: %s) (every %d sec)\n", shortID, heartbeatSec)
			fmt.Printf("  Delta Tested: %.0f\n", delta)
			fmt.Printf("  Total Attempts: %.0f\n", total)
			fmt.Printf("  Threads Active: %d\n", threadsActive)
			fmt.Printf("  Current Rate: %.2f hashes/sec\n", rate)

		case "result":
			_ = sendMsg(conn, map[string]any{"type": "result_ack"})

			latMsg, err := recvMsg(conn)
			if err != nil {
				fmt.Printf("  WARNING: Failed to receive result latency from worker %s\n", shortID)
			}

			rrl := 0.0
			if latMsg != nil {
				rrl = floatFromAny(latMsg["result_return_latency"])
			}
			worker.ResultReturnLatency = &rrl

			report_result(ctx, worker, shortID, msg)

		case "disconnect":
			ctx.WorkersMu.Lock()
			delete(ctx.Workers, worker.ID)
			ctx.WorkersMu.Unlock()
			_ = conn.Close()
			fmt.Printf("\nWORKER DISCONNECTED (WorkerID: %s) - worker exited\n", shortID)
			return

		default:
			fmt.Printf("  Received unexpected message from worker %s: %s\n", shortID, typ)
		}
	}
}

// register_worker accepts and records a worker registration so it can
// participate in cracking.
func register_worker(ctx *Context, conn net.Conn, addr string) (*WorkerInfo, error) {
	fmt.Println("  Waiting for worker to send registration request...")

	registrationReq, err := recvWithTimeout(conn, 5*time.Second)
	if err != nil {
		return nil, err
	}

	fmt.Println("  Worker registration request received")

	if typ, _ := registrationReq["type"].(string); typ != "register" {
		_ = sendMsg(conn, map[string]any{
			"type":   "registration_err",
			"reason": "bad register",
		})
		return nil, fmt.Errorf("bad registration type: %s", typ)
	}

	ctx.WorkersMu.Lock()
	workerID := fmt.Sprintf("%d", ctx.NextWorkerID)
	ctx.NextWorkerID++
	ctx.WorkersMu.Unlock()

	_ = sendMsg(conn, map[string]any{
		"type":      "registration_ok",
		"worker_id": workerID,
	})

	worker := &WorkerInfo{
		Conn: conn,
		ID:   workerID,
		Addr: addr,
	}

	ctx.WorkersMu.Lock()
	ctx.Workers[workerID] = worker
	ctx.WorkersMu.Unlock()

	fmt.Printf("  Worker registered successfully (WorkerID: %s)\n", workerID)
	return worker, nil
}

// send_chunk assigns the next available portion of the search space to a
// requesting worker. For now sends the full search space (no chunking yet).
func send_chunk(ctx *Context, worker *WorkerInfo, shortID string) {
	ctx.WorkersMu.Lock()
	jobID := ctx.NextJobID
	ctx.NextJobID++
	worker.JobID = jobID
	worker.HasJob = true
	ctx.WorkersMu.Unlock()

	now := time.Now()
	worker.RuntimeStart = &now

	charset := "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"0123456789" +
		"@#%^&*()_+-=.,:;?"

	job := map[string]any{
		"type":        "job",
		"job_id":      jobID,
		"username":    ctx.Settings.Username,
		"alg_id":      ctx.PwInfo.AlgID,
		"salt":        ctx.PwInfo.Salt,
		"hash":        ctx.PwInfo.Hash,
		"hash_full":   ctx.PwInfo.Full,
		"charset":     charset,
		"hb_interval": ctx.Settings.HeartbeatInterval,
	}

	dispatchStart := time.Now()
	if err := sendMsg(worker.Conn, job); err != nil {
		ctx.WorkersMu.Lock()
		delete(ctx.Workers, worker.ID)
		ctx.WorkersMu.Unlock()
		_ = worker.Conn.Close()
		fmt.Printf("\nWORKER DISCONNECTED (WorkerID: %s) - failed to send job\n", shortID)
		return
	}

	ack, err := recvMsg(worker.Conn)
	if err != nil {
		ctx.WorkersMu.Lock()
		delete(ctx.Workers, worker.ID)
		ctx.WorkersMu.Unlock()
		_ = worker.Conn.Close()
		fmt.Printf("\nWORKER DISCONNECTED (WorkerID: %s) - no job ack\n", shortID)
		return
	}

	dispatchEnd := time.Now()
	lat := dispatchEnd.Sub(dispatchStart).Seconds()
	worker.DispatchLatency = &lat

	ackType := strFromAny(ack["type"])
	ackJobID := intFromAny(ack["job_id"])
	if ackType != "job_ack" || ackJobID != jobID {
		fmt.Printf("  WARNING: Unexpected ack from worker %s: %v\n", shortID, ack)
	}

	fmt.Printf("\nDISPATCHED JOB #%d (WorkerID: %s)\n", jobID, shortID)
	fmt.Printf("  Dispatch Latency: %.2f milliseconds (C -> W)\n", lat*1000)
}

// report_result displays the final cracking result and timing breakdown
// for a single worker's completed job.
func report_result(ctx *Context, worker *WorkerInfo, shortID string, msg map[string]any) {
	found := boolFromAny(msg["found"])
	var statusValue string
	var passwordValue string
	if found {
		statusValue = "SUCCESS"
		passwordValue, _ = msg["password"].(string)
	} else {
		statusValue = "FAILED"
		passwordValue = "N/A"
	}

	attempts := floatFromAny(msg["attempts"])
	crackTime := floatFromAny(msg["compute_time"])

	hps := 0.0
	if crackTime > 0 {
		hps = attempts / crackTime
	}

	parseMs := 0.0
	if ctx.ParseTime != nil {
		parseMs = (*ctx.ParseTime) * 1000
	}
	dispatchMs := 0.0
	if worker.DispatchLatency != nil {
		dispatchMs = (*worker.DispatchLatency) * 1000
	}
	resultMs := 0.0
	if worker.ResultReturnLatency != nil {
		resultMs = (*worker.ResultReturnLatency) * 1000
	}

	runtime := 0.0
	if worker.RuntimeStart != nil {
		runtime = time.Since(*worker.RuntimeStart).Seconds()
	}

	fmt.Println("\n" + strings.Repeat("=", 40))
	fmt.Printf("     CRACKING RESULTS (WorkerID: %s)\n", shortID)
	fmt.Println(strings.Repeat("=", 40))

	labelWidth := 20
	fmt.Printf("%-*s %s\n", labelWidth, "STATUS:", statusValue)
	fmt.Printf("%-*s %s\n", labelWidth, "PASSWORD:", passwordValue)
	fmt.Printf("%-*s %.0f\n", labelWidth, "ATTEMPTS:", attempts)
	fmt.Printf("%-*s %.2f seconds\n", labelWidth, "TIME:", crackTime)
	fmt.Printf("%-*s %.2f hashes/sec\n", labelWidth, "SPEED:", hps)
	fmt.Printf("%-*s %.2f milliseconds\n", labelWidth, "PARSING TIME:", parseMs)
	fmt.Printf("%-*s %.2f milliseconds\n", labelWidth, "DISPATCH LATENCY:", dispatchMs)
	fmt.Printf("%-*s %.2f milliseconds\n", labelWidth, "RESULT LATENCY:", resultMs)
	fmt.Printf("%-*s %.2f seconds\n", labelWidth, "E2E RUNTIME:", runtime)
	fmt.Println(strings.Repeat("=", 40))
}

// monitor_progress tracks all active workers and receives updates.
// Blocks forever — per-worker goroutines handle all the work.
// Controller exits only via SIGINT/SIGTERM → cleanup.
func monitor_progress(_ *Context) State {
	select {}
}

func state_error(ctx *Context) State {
	fmt.Printf("\n%s\n", ctx.ExitMessage)
	return StateCleanup
}

func cleanup(ctx *Context) State {
	ctx.WorkersMu.Lock()
	for _, w := range ctx.Workers {
		_ = w.Conn.Close()
	}
	ctx.WorkersMu.Unlock()

	if ctx.ServerLn != nil {
		_ = ctx.ServerLn.Close()
	}

	fmt.Println("\nEXITING PROGRAM")
	os.Exit(0)
	return StateCleanup
}

func main() {
	fmt.Println("--- CONTROLLER ---")

	ctx := &Context{
		Workers:      make(map[string]*WorkerInfo),
		NextJobID:    1,
		NextWorkerID: 1,
	}

	handlers := map[State]Handler{
		StateParseArgs:       parse_arguments,
		StateHandleArgs:      handle_arguments,
		StateParseShadow:     parse_shadow,
		StateListen:          listen,
		StateMonitorProgress: monitor_progress,
		StateError:           state_error,
		StateCleanup:         cleanup,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		handlers[StateCleanup](ctx)
	}()

	state := StateParseArgs
	for {
		h := handlers[state]
		state = h(ctx)
	}
}

func sendMsg(conn net.Conn, msg map[string]any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))

	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err = conn.Write(b)
	return err
}

// ---------- Messaging ----------

func recvMsg(conn net.Conn) (map[string]any, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > 50_000_000 {
		return nil, fmt.Errorf("invalid message length: %d", n)
	}

	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	var out map[string]any
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func recvWithTimeout(conn net.Conn, timeout time.Duration) (map[string]any, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	msg, err := recvMsg(conn)
	_ = conn.SetReadDeadline(time.Time{})
	return msg, err
}

// ---------- Helpers ----------

func intFromAny(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case json.Number:
		i, _ := x.Int64()
		return int(i)
	default:
		return 0
	}
}

func floatFromAny(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case json.Number:
		f, _ := x.Float64()
		return f
	default:
		return 0
	}
}

func strFromAny(v any) string {
	s, _ := v.(string)
	return s
}

func boolFromAny(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	default:
		return false
	}
}
