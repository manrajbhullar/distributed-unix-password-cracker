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
	"sync/atomic"
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
	ChunkSize         int
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
	HasJob bool

	CurrentJobID      int
	CurrentChunkStart int64
	CurrentChunkSize  int

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

	NextChunkStart int64
	FoundFlag      int32 // atomic
	FoundPassword  string
	FoundByWorker  string
	FoundByJobID   int
	FoundTime      time.Time

	WorkerWG sync.WaitGroup // counts active handleWorker goroutines

	TotalAttempts  int64 // atomic, accumulated across all chunks
	CrackStartTime *time.Time

	DispatchLatencies []float64
	ResultLatencies   []float64
	ComputeTimes      []float64

	Done chan struct{}

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
	var chunkSize int

	fs.StringVar(&filename, "f", "", "Name of shadow file")
	fs.StringVar(&username, "u", "", "Username whose password being cracked")
	fs.IntVar(&port, "p", 0, "Port number control server runs on")
	fs.IntVar(&heartbeat, "b", -1, "Heartbeat interval in seconds")
	fs.IntVar(&chunkSize, "c", 0, "Chunk size in number of candidates per job")

	if err := fs.Parse(os.Args[1:]); err != nil {
		ctx.ExitMessage = err.Error()
		return StateError
	}

	if filename == "" || username == "" || port == 0 || heartbeat == -1 || chunkSize == 0 {
		fmt.Fprintln(os.Stderr, "Missing required flags: -f -u -p -b -c")
		fs.Usage()
		ctx.ExitMessage = "Missing required flags"
		return StateError
	}

	ctx.Settings.Filename = filename
	ctx.Settings.Username = username
	ctx.Settings.Port = port
	ctx.Settings.HeartbeatInterval = heartbeat
	ctx.Settings.ChunkSize = chunkSize

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

	if ctx.Settings.ChunkSize <= 0 {
		ctx.ExitMessage = "ERROR: Chunk size must be greater than 0"
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
			// sha256/sha512: either $5$rounds=N$salt$hash (5 tokens)
			// or $5$salt$hash (4 tokens, default rounds)
			if strings.HasPrefix(tokens[2], "rounds=") {
				if len(tokens) < 5 {
					ctx.ExitMessage = "ERROR: User hash failed to tokenize"
					return StateError
				}
				ctx.PwInfo.Salt = tokens[3]
				ctx.PwInfo.Hash = tokens[4]
			} else {
				if len(tokens) < 4 {
					ctx.ExitMessage = "ERROR: User hash failed to tokenize"
					return StateError
				}
				ctx.PwInfo.Salt = tokens[2]
				ctx.PwInfo.Hash = tokens[3]
			}
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
	fmt.Printf("\nWAITING TO REGISTER WORKERS (Active: 0)\n")

	// Accept loop — continuously accepts new worker connections
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // Listener closed during cleanup
			}
			ctx.WorkerWG.Add(1)
			go func() {
				defer ctx.WorkerWG.Done()
				handleWorker(ctx, conn)
			}()
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

	workerID := worker.ID
	hbTimeout := time.Duration(ctx.Settings.HeartbeatInterval)*time.Second + 500*time.Millisecond

	// Per-worker message loop
	for {
		_ = conn.SetReadDeadline(time.Now().Add(hbTimeout))
		msg, err := recvMsg(conn)
		_ = conn.SetReadDeadline(time.Time{})
		if err != nil {
			ctx.WorkersMu.Lock()
			delete(ctx.Workers, worker.ID)
			ctx.WorkersMu.Unlock()
			_ = conn.Close()
			if atomic.LoadInt32(&ctx.FoundFlag) == 0 {
				netErr, ok := err.(net.Error)
				if ok && netErr.Timeout() {
					fmt.Printf("\nWORKER TIMEOUT (WorkerID: %s) - missed heartbeat\n", workerID)
				} else {
					fmt.Printf("\nWORKER DISCONNECTED (WorkerID: %s) - connection lost\n", workerID)
				}
				ctx.WorkersMu.Lock()
				activeCount := len(ctx.Workers)
				ctx.WorkersMu.Unlock()
				if activeCount == 0 {
					fmt.Printf("\nWAITING TO REGISTER WORKERS (Active: 0)\n")
				}
			}
			return
		}

		typ := strFromAny(msg["type"])

		switch typ {
		case "job_request":
			send_chunk(ctx, worker, workerID)

		case "heartbeat_resp":
			delta := floatFromAny(msg["delta_tested"])
			total := floatFromAny(msg["total_tested"])
			threadsActive := intFromAny(msg["threads_active"])
			rate := floatFromAny(msg["current_rate"])

			fmt.Printf("\nHEARTBEAT (WorkerID: %s)\n", workerID)
			fmt.Printf("  Delta Tested: %.0f\n", delta)
			fmt.Printf("  Total Attempts: %.0f\n", total)
			fmt.Printf("  Threads Active: %d\n", threadsActive)
			fmt.Printf("  Current Rate: %.2f hashes/sec\n", rate)
			fmt.Printf("  Current Job: %d\n", worker.CurrentJobID)

		case "result":
			_ = sendMsg(conn, map[string]any{"type": "result_ack"})

			latMsg, err := recvMsg(conn)
			if err != nil {
				fmt.Printf("  WARNING: Failed to receive result latency from worker %s\n", workerID)
			}

			rrl := 0.0
			if latMsg != nil {
				rrl = floatFromAny(latMsg["result_return_latency"])
			}
			worker.ResultReturnLatency = &rrl

			found := boolFromAny(msg["found"])
			chunkEnd := worker.CurrentChunkStart + int64(worker.CurrentChunkSize)
			attempts := floatFromAny(msg["attempts"])
			atomic.AddInt64(&ctx.TotalAttempts, int64(attempts))
			crackTime := floatFromAny(msg["compute_time"])
			hps := 0.0
			if crackTime > 0 {
				hps = attempts / crackTime
			}
			resultMs := 0.0
			if worker.ResultReturnLatency != nil {
				resultMs = (*worker.ResultReturnLatency) * 1000
			}
			dispatchMs := 0.0
			if worker.DispatchLatency != nil {
				dispatchMs = (*worker.DispatchLatency) * 1000
			}
			ctx.WorkersMu.Lock()
			if worker.DispatchLatency != nil {
				ctx.DispatchLatencies = append(ctx.DispatchLatencies, *worker.DispatchLatency)
			}
			ctx.ResultLatencies = append(ctx.ResultLatencies, rrl)
			ctx.ComputeTimes = append(ctx.ComputeTimes, crackTime)
			ctx.WorkersMu.Unlock()
			fmt.Printf("\nJOB #%d COMPLETE (WorkerID: %s)\n", worker.CurrentJobID, workerID)
			fmt.Printf("  Status: %s\n", strFromAny(msg["status"]))
			fmt.Printf("  Chunk: %d to %d\n", worker.CurrentChunkStart, chunkEnd)
			fmt.Printf("  Attempts: %.0f\n", attempts)
			fmt.Printf("  Time: %.2f seconds\n", crackTime)
			fmt.Printf("  Speed: %.2f hashes/sec\n", hps)
			fmt.Printf("  Dispatch Latency: %.2f ms\n", dispatchMs)
			fmt.Printf("  Result Latency: %.2f ms\n", resultMs)

			if found {
				// First worker to find the password wins
				if atomic.CompareAndSwapInt32(&ctx.FoundFlag, 0, 1) {
					ctx.WorkersMu.Lock()
					ctx.FoundPassword, _ = msg["password"].(string)
					ctx.FoundByWorker = worker.ID
					ctx.FoundByJobID = intFromAny(msg["job_id"])
					ctx.FoundTime = time.Now()
					// Broadcast force_stop to all other active workers immediately
					for id, w := range ctx.Workers {
						if id != worker.ID {
							_ = sendMsg(w.Conn, map[string]any{"type": "force_stop"})
						}
					}
					ctx.WorkersMu.Unlock()
					// Stop accepting new connections so WorkerWG can drain cleanly
					_ = ctx.ServerLn.Close()
					close(ctx.Done)
				}
			}

		case "disconnect":
			ctx.WorkersMu.Lock()
			delete(ctx.Workers, worker.ID)
			ctx.WorkersMu.Unlock()
			_ = conn.Close()
			if atomic.LoadInt32(&ctx.FoundFlag) == 0 {
				fmt.Printf("\nWORKER DISCONNECTED (WorkerID: %s) - worker exited\n", workerID)
				ctx.WorkersMu.Lock()
				activeCount := len(ctx.Workers)
				ctx.WorkersMu.Unlock()
				if activeCount == 0 {
					fmt.Printf("\nWAITING TO REGISTER WORKERS (Active: 0)\n")
				}
			}
			return

		case "force_stop_ack":
			attempts := floatFromAny(msg["attempts"])
			atomic.AddInt64(&ctx.TotalAttempts, int64(attempts))

		default:
			fmt.Printf("  Received unexpected message from worker %s: %s\n", workerID, typ)
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
		"username":  ctx.Settings.Username,
		"alg_id":    ctx.PwInfo.AlgID,
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
// requesting worker, or sends STOP if the password has already been found.
func send_chunk(ctx *Context, worker *WorkerInfo, workerID string) {
	// If password already found, tell this worker to stop
	if atomic.LoadInt32(&ctx.FoundFlag) == 1 {
		_ = sendMsg(worker.Conn, map[string]any{"type": "stop"})
		return
	}

	ctx.WorkersMu.Lock()
	jobID := ctx.NextJobID
	ctx.NextJobID++
	chunkStart := ctx.NextChunkStart
	chunkSize := ctx.Settings.ChunkSize
	ctx.NextChunkStart += int64(chunkSize)
	worker.CurrentJobID = jobID
	worker.CurrentChunkStart = chunkStart
	worker.CurrentChunkSize = chunkSize
	worker.HasJob = true
	if ctx.CrackStartTime == nil {
		now := time.Now()
		ctx.CrackStartTime = &now
	}
	ctx.WorkersMu.Unlock()

	if worker.RuntimeStart == nil {
		now := time.Now()
		worker.RuntimeStart = &now
	}

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
		"chunk_start": chunkStart,
		"chunk_size":  chunkSize,
		"hb_interval": ctx.Settings.HeartbeatInterval,
	}

	dispatchStart := time.Now()
	if err := sendMsg(worker.Conn, job); err != nil {
		ctx.WorkersMu.Lock()
		delete(ctx.Workers, worker.ID)
		ctx.WorkersMu.Unlock()
		_ = worker.Conn.Close()
		if atomic.LoadInt32(&ctx.FoundFlag) == 0 {
			fmt.Printf("\nWORKER DISCONNECTED (WorkerID: %s) - failed to send job\n", workerID)
		}
		return
	}

	var ack map[string]any
	for {
		msg, err := recvMsg(worker.Conn)
		if err != nil {
			ctx.WorkersMu.Lock()
			delete(ctx.Workers, worker.ID)
			ctx.WorkersMu.Unlock()
			_ = worker.Conn.Close()
			if atomic.LoadInt32(&ctx.FoundFlag) == 0 {
				fmt.Printf("\nWORKER DISCONNECTED (WorkerID: %s) - no job ack\n", workerID)
			}
			return
		}
		if strFromAny(msg["type"]) == "heartbeat_resp" {
			delta := floatFromAny(msg["delta_tested"])
			total := floatFromAny(msg["total_tested"])
			threadsActive := intFromAny(msg["threads_active"])
			rate := floatFromAny(msg["current_rate"])
			fmt.Printf("\nHEARTBEAT (WorkerID: %s)\n", workerID)
			fmt.Printf("  Delta Tested: %.0f\n", delta)
			fmt.Printf("  Total Attempts: %.0f\n", total)
			fmt.Printf("  Threads Active: %d\n", threadsActive)
			fmt.Printf("  Current Rate: %.2f hashes/sec\n", rate)
			fmt.Printf("  Current Job: %d\n", worker.CurrentJobID)
			continue
		}
		ack = msg
		break
	}

	dispatchEnd := time.Now()
	lat := dispatchEnd.Sub(dispatchStart).Seconds()
	worker.DispatchLatency = &lat

	ackType := strFromAny(ack["type"])
	ackJobID := intFromAny(ack["job_id"])
	if ackType != "job_ack" || ackJobID != jobID {
		fmt.Printf("  WARNING: Unexpected ack from worker %s: %v\n", workerID, ack)
	}

	fmt.Printf("\nDISPATCHED JOB #%d (WorkerID: %s)\n", jobID, workerID)
	fmt.Printf("  Chunk: %d to %d\n", chunkStart, chunkStart+int64(chunkSize))
	fmt.Printf("  Dispatch Latency: %.2f milliseconds (C -> W)\n", lat*1000)
}

// report_result displays the overall cracking summary once the password is found.
func report_result(ctx *Context) {
	passwordValue := ctx.FoundPassword

	totalAttempts := atomic.LoadInt64(&ctx.TotalAttempts)

	e2e := 0.0
	if ctx.CrackStartTime != nil {
		e2e = time.Since(*ctx.CrackStartTime).Seconds()
	}

	parseMs := 0.0
	if ctx.ParseTime != nil {
		parseMs = (*ctx.ParseTime) * 1000
	}

	avgDispatchMs := 0.0
	avgResultMs := 0.0
	totalComputeS := 0.0
	ctx.WorkersMu.Lock()
	if len(ctx.DispatchLatencies) > 0 {
		sum := 0.0
		for _, v := range ctx.DispatchLatencies {
			sum += v
		}
		avgDispatchMs = (sum / float64(len(ctx.DispatchLatencies))) * 1000
	}
	if len(ctx.ResultLatencies) > 0 {
		sum := 0.0
		for _, v := range ctx.ResultLatencies {
			sum += v
		}
		avgResultMs = (sum / float64(len(ctx.ResultLatencies))) * 1000
	}
	if len(ctx.ComputeTimes) > 0 {
		for _, v := range ctx.ComputeTimes {
			totalComputeS += v
		}
	}
	ctx.WorkersMu.Unlock()

	overallHps := 0.0
	if totalComputeS > 0 {
		overallHps = float64(totalAttempts) / totalComputeS
	}

	const boxWidth = 45
	title := "CRACKING RESULTS"
	pad := strings.Repeat(" ", (boxWidth-len(title))/2)
	fmt.Println("\n" + strings.Repeat("=", boxWidth))
	fmt.Printf("%s%s\n", pad, title)
	fmt.Println(strings.Repeat("=", boxWidth))
	fmt.Printf("STATUS: SUCCESS\n")
	fmt.Printf("PASSWORD: %s\n", passwordValue)
	fmt.Printf("TOTAL ATTEMPTS: %d\n", totalAttempts)
	fmt.Printf("COMPUTE TIME: %.2f seconds\n", totalComputeS)
	fmt.Printf("E2E RUNTIME: %.2f seconds\n", e2e)
	fmt.Printf("OVERALL SPEED: %.2f hashes/sec\n", overallHps)
	fmt.Printf("PARSING TIME: %.2f milliseconds\n", parseMs)
	fmt.Printf("DISPATCH LATENCY (AVG): %.2f milliseconds\n", avgDispatchMs)
	fmt.Printf("RESULT LATENCY (AVG): %.2f milliseconds\n", avgResultMs)
	fmt.Printf("CRACKED BY: Worker #%s in Job #%d\n", ctx.FoundByWorker, ctx.FoundByJobID)
	fmt.Println(strings.Repeat("=", boxWidth))
}

// monitor_progress tracks all active workers and receives updates.
// Blocks until a worker finds the password or SIGINT/SIGTERM triggers cleanup.
func monitor_progress(ctx *Context) State {
	<-ctx.Done
	// Wait for all handleWorker goroutines to finish so their force_stop_ack
	// partial attempt counts are fully accumulated before reporting results.
	waitCh := make(chan struct{})
	go func() { ctx.WorkerWG.Wait(); close(waitCh) }()
	select {
	case <-waitCh:
	case <-time.After(5 * time.Second):
	}
	report_result(ctx)
	return StateCleanup
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
		Done:         make(chan struct{}),
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
