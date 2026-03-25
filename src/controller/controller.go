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
	StateMonitorProgress
	StateError
	StateCleanup
)

type Settings struct {
	Filename           string
	Username           string
	Port               int
	HeartbeatInterval  int
	ChunkSize          int
	CheckpointInterval int
}

type PasswordInfo struct {
	AlgID string
	Salt  string
	Hash  string
	Full  string
}

type WorkerInfo struct {
	Conn         net.Conn
	SendMu       sync.Mutex
	IncomingMsgs chan map[string]any
	HBAck        chan struct{}
	ID           string
	Addr         string
	HasJob       bool

	CurrentJobID      int
	CurrentChunkStart int64
	CurrentChunkSize  int
	LastCheckpoint    int64

	RuntimeStart        *time.Time
	DispatchLatency     *float64
	ResultReturnLatency *float64

	PendingReassign *RemainingChunk
}

type StoppedJob struct {
	WorkerID string
	JobID    int
	Attempts int64
}

type RemainingChunk struct {
	JobID int
	Start int64
	Size  int
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
	FoundFlag      int32
	FoundPassword  string
	FoundByWorker  string
	FoundByJobID   int
	FoundTime      time.Time
	E2E            float64

	WorkerWG sync.WaitGroup

	TotalAttempts      int64
	TotalCheckpoints   int64
	CrackStartTime *time.Time

	DispatchLatencies []float64
	ResultLatencies   []float64
	ComputeTimes      map[string][]float64
	StoppedJobs       []StoppedJob
	RemainingChunks   []RemainingChunk

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
	var checkpointInterval int

	fs.StringVar(&filename, "f", "", "Name of shadow file")
	fs.StringVar(&username, "u", "", "Username whose password being cracked")
	fs.IntVar(&port, "p", 0, "Port number control server runs on")
	fs.IntVar(&heartbeat, "b", -1, "Heartbeat interval in seconds")
	fs.IntVar(&chunkSize, "c", 0, "Chunk size in number of candidates per job")
	fs.IntVar(&checkpointInterval, "k", 0, "Checkpoint interval in candidate attempts")

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
	ctx.Settings.CheckpointInterval = checkpointInterval

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

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			ctx.WorkerWG.Add(1)
			go func() {
				defer ctx.WorkerWG.Done()
				handle_worker(ctx, conn)
			}()
		}
	}()

	return StateMonitorProgress
}

func handle_worker(ctx *Context, conn net.Conn) {
	addr := conn.RemoteAddr().String()
	fmt.Printf("\nWORKER CONNECTED FROM: %s\n", addr)

	worker, err := register_worker(ctx, conn, addr)
	if err != nil {
		fmt.Printf("  ERROR: Worker from %s failed to register. %v\n", addr, err)
		_ = conn.Close()
		return
	}

	workerID := worker.ID
	hbInterval := time.Duration(ctx.Settings.HeartbeatInterval) * time.Second

	hbDone := make(chan struct{})
	worker.HBAck = make(chan struct{}, 1)
	maxMissedHB := 3
	hbDead := make(chan struct{})
	go func() {
		timer := time.NewTimer(hbInterval)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done:
				return
			case <-timer.C:
				if atomic.LoadInt32(&ctx.FoundFlag) == 1 {
					return
				}
				worker.SendMu.Lock()
				err := sendMsg(conn, map[string]any{"type": "heartbeat_req"})
				worker.SendMu.Unlock()
				if err != nil {
					return
				}
				missWindow := hbInterval / time.Duration(maxMissedHB)
				missed := 0
			waitLoop:
				for {
					select {
					case <-worker.HBAck:
						timer.Reset(hbInterval)
						break waitLoop
					case <-time.After(missWindow):
						missed++
						if atomic.LoadInt32(&ctx.FoundFlag) == 0 {
							fmt.Printf("\nWORKER MISSED HEARTBEAT (WorkerID: %s) - %d/%d Attempts\n", workerID, missed, maxMissedHB)
						}
						if missed >= maxMissedHB {
							close(hbDead)
							return
						}
					case <-ctx.Done:
						return
					case <-hbDone:
						return
					}
				}
			case <-hbDone:
				return
			}
		}
	}()
	defer close(hbDone)

	monitor_worker(worker)

	for {
		select {
		case msg, ok := <-worker.IncomingMsgs:
			if !ok {
				ctx.WorkersMu.Lock()
				delete(ctx.Workers, worker.ID)
				ctx.WorkersMu.Unlock()
				_ = conn.Close()
				if atomic.LoadInt32(&ctx.FoundFlag) == 0 {
					fmt.Printf("\nWORKER DISCONNECTED (WorkerID: %s) - connection lost\n", workerID)
					queue_reassignment(ctx, worker)
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
				receive_heartbeat(worker, msg, hbDead)

			case "result":
				receive_job_result(ctx, worker, msg, hbDead)

			case "checkpoint":
				receive_checkpoint(ctx, worker, msg)

			case "disconnect":
				disconnect_worker(ctx, worker)
				return

			case "force_stop_ack":
				record_stop_point(ctx, worker, msg)

			default:
				fmt.Printf("  Received unexpected message from worker %s: %s\n", workerID, typ)
			}

		case <-ctx.Done:
			if worker.ID == ctx.FoundByWorker {
				return
			}
			deadline := time.After(3 * time.Second)
			for {
				select {
				case msg, ok := <-worker.IncomingMsgs:
					if !ok {
						return
					}
					if strFromAny(msg["type"]) == "force_stop_ack" {
						record_stop_point(ctx, worker, msg)
						return
					}
				case <-deadline:
					return
				}
			}

		case <-hbDead:
			ctx.WorkersMu.Lock()
			delete(ctx.Workers, worker.ID)
			ctx.WorkersMu.Unlock()
			_ = conn.Close()
			if atomic.LoadInt32(&ctx.FoundFlag) == 0 {
				fmt.Printf("\nWORKER TIMEOUT (WorkerID: %s) - missed heartbeat\n", workerID)
				queue_reassignment(ctx, worker)
				ctx.WorkersMu.Lock()
				activeCount := len(ctx.Workers)
				ctx.WorkersMu.Unlock()
				if activeCount == 0 {
					fmt.Printf("\nWAITING TO REGISTER WORKERS (Active: 0)\n")
				}
			}
			return
		}
	}
}

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

func monitor_worker(worker *WorkerInfo) {
	worker.IncomingMsgs = make(chan map[string]any, 16)
	go func() {
		for {
			msg, err := recvMsg(worker.Conn)
			if err != nil {
				close(worker.IncomingMsgs)
				return
			}
			worker.IncomingMsgs <- msg
		}
	}()
}

func disconnect_worker(ctx *Context, worker *WorkerInfo) {
	ctx.WorkersMu.Lock()
	delete(ctx.Workers, worker.ID)
	ctx.WorkersMu.Unlock()
	_ = worker.Conn.Close()
	if atomic.LoadInt32(&ctx.FoundFlag) == 0 {
		fmt.Printf("\nWORKER DISCONNECTED (WorkerID: %s) - worker exited\n", worker.ID)
		if worker.PendingReassign != nil {
			rc := worker.PendingReassign
			fmt.Printf("\nJOB #%d QUEUED FOR REASSIGNMENT (Remaining Chunk: %d to %d)\n", rc.JobID, rc.Start, rc.Start+int64(rc.Size))
		}
		ctx.WorkersMu.Lock()
		activeCount := len(ctx.Workers)
		ctx.WorkersMu.Unlock()
		if activeCount == 0 {
			fmt.Printf("\nWAITING TO REGISTER WORKERS (Active: 0)\n")
		}
	}
}

func record_stop_point(ctx *Context, worker *WorkerInfo, msg map[string]any) {
	attempts := int64(floatFromAny(msg["attempts"]))
	atomic.AddInt64(&ctx.TotalAttempts, attempts)
	ctx.WorkersMu.Lock()
	ctx.StoppedJobs = append(ctx.StoppedJobs, StoppedJob{
		WorkerID: worker.ID,
		JobID:    worker.CurrentJobID,
		Attempts: attempts,
	})
	ctx.WorkersMu.Unlock()
}

func queue_reassignment(ctx *Context, worker *WorkerInfo) {
	if worker.HasJob {
		chunkEnd := worker.CurrentChunkStart + int64(worker.CurrentChunkSize)
		remainStart := worker.LastCheckpoint
		remainSize := int(chunkEnd - remainStart)
		if remainSize > 0 {
			rc := RemainingChunk{
				JobID: worker.CurrentJobID,
				Start: remainStart,
				Size:  remainSize,
			}
			ctx.WorkersMu.Lock()
			ctx.RemainingChunks = append(ctx.RemainingChunks, rc)
			ctx.WorkersMu.Unlock()
			fmt.Printf("\nJOB #%d QUEUED FOR REASSIGNMENT (Remaining Chunk: %d to %d)\n", rc.JobID, rc.Start, rc.Start+int64(rc.Size))
		}
	}
}

func receive_job_result(ctx *Context, worker *WorkerInfo, msg map[string]any, hbDead chan struct{}) {
	workerID := worker.ID

	worker.SendMu.Lock()
	_ = sendMsg(worker.Conn, map[string]any{"type": "result_ack"})
	worker.SendMu.Unlock()

	var latMsg map[string]any
latLoop:
	for {
		select {
		case lm, ok := <-worker.IncomingMsgs:
			if !ok {
				fmt.Printf("  WARNING: Failed to receive result latency from worker %s\n", workerID)
				break latLoop
			}
			if strFromAny(lm["type"]) == "heartbeat_resp" {
				log_heartbeat(worker, lm)
				select {
				case worker.HBAck <- struct{}{}:
				default:
				}
				continue
			}
			latMsg = lm
			break latLoop
		case <-time.After(5 * time.Second):
			fmt.Printf("  WARNING: Failed to receive result latency from worker %s\n", workerID)
			break latLoop
		}
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
	hps := floatFromAny(msg["hps"])
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
	ctx.ComputeTimes[workerID] = append(ctx.ComputeTimes[workerID], crackTime)
	ctx.WorkersMu.Unlock()
	jobLabel := "COMPLETE"
	if strFromAny(msg["status"]) == "Manually Interrupted" {
		jobLabel = "INCOMPLETE"
	}
	fmt.Printf("\nJOB #%d %s (WorkerID: %s)\n", worker.CurrentJobID, jobLabel, workerID)
	fmt.Printf("  Status: %s\n", strFromAny(msg["status"]))
	fmt.Printf("  Chunk: %d to %d\n", worker.CurrentChunkStart, chunkEnd)
	fmt.Printf("  Attempts: %.0f\n", attempts)
	fmt.Printf("  Compute Time: %.2f seconds\n", crackTime)
	fmt.Printf("  Speed: %.2f hashes/sec\n", hps)
	fmt.Printf("  Dispatch Latency: %.2f ms\n", dispatchMs)
	fmt.Printf("  Result Latency: %.2f ms\n", resultMs)

	if strFromAny(msg["status"]) == "Manually Interrupted" {
		remainStart := worker.CurrentChunkStart + int64(attempts)
		remainSize := int(int64(worker.CurrentChunkSize) - int64(attempts))
		if remainSize > 0 {
			rc := RemainingChunk{
				JobID: worker.CurrentJobID,
				Start: remainStart,
				Size:  remainSize,
			}
			ctx.WorkersMu.Lock()
			ctx.RemainingChunks = append(ctx.RemainingChunks, rc)
			ctx.WorkersMu.Unlock()
			worker.PendingReassign = &rc
		}
	}

	if found {
		send_stop_all(ctx, worker, msg)
	}
}

func send_stop_all(ctx *Context, worker *WorkerInfo, msg map[string]any) {
	if atomic.CompareAndSwapInt32(&ctx.FoundFlag, 0, 1) {
		ctx.WorkersMu.Lock()
		ctx.FoundPassword, _ = msg["password"].(string)
		ctx.FoundByWorker = worker.ID
		ctx.FoundByJobID = intFromAny(msg["job_id"])
		ctx.FoundTime = time.Now()
		ctx.E2E = ctx.FoundTime.Sub(*ctx.CrackStartTime).Seconds()
		for id, w := range ctx.Workers {
			if id != worker.ID {
				w.SendMu.Lock()
				_ = sendMsg(w.Conn, map[string]any{"type": "force_stop"})
				w.SendMu.Unlock()
			}
		}
		ctx.WorkersMu.Unlock()
		_ = ctx.ServerLn.Close()
		close(ctx.Done)
	}
}

func receive_checkpoint(ctx *Context, worker *WorkerInfo, msg map[string]any) {
	cpAttempts := int64(floatFromAny(msg["attempts"]))
	worker.LastCheckpoint = worker.CurrentChunkStart + cpAttempts
	atomic.AddInt64(&ctx.TotalCheckpoints, 1)
	fmt.Printf("\nCHECKPOINT (WorkerID: %s)\n", worker.ID)
	pct := float64(cpAttempts) / float64(worker.CurrentChunkSize) * 100
	fmt.Printf("  Position: %d\n", worker.LastCheckpoint)
	fmt.Printf("  Attempts into Job: %d\n", cpAttempts)
	fmt.Printf("  Current Progress: %.1f%%\n", pct)
	fmt.Printf("  Current Job: %d\n", worker.CurrentJobID)
	fmt.Printf("  Current Chunk: %d to %d\n", worker.CurrentChunkStart, worker.CurrentChunkStart+int64(worker.CurrentChunkSize))
}

func receive_heartbeat(worker *WorkerInfo, msg map[string]any, hbDead chan struct{}) {
	select {
	case <-hbDead:
	default:
		log_heartbeat(worker, msg)
		select {
		case worker.HBAck <- struct{}{}:
		default:
		}
	}
}

func log_heartbeat(worker *WorkerInfo, msg map[string]any) {
	delta := floatFromAny(msg["delta_tested"])
	total := floatFromAny(msg["total_tested"])
	threadsActive := intFromAny(msg["threads_active"])
	rate := floatFromAny(msg["current_rate"])

	fmt.Printf("\nHEARTBEAT (WorkerID: %s)\n", worker.ID)
	fmt.Printf("  Delta Tested: %.0f\n", delta)
	fmt.Printf("  Total Attempts: %.0f\n", total)
	fmt.Printf("  Threads Active: %d\n", threadsActive)
	fmt.Printf("  Current Rate: %.2f hashes/sec\n", rate)
	fmt.Printf("  Current Job: %d\n", worker.CurrentJobID)
}

func send_chunk(ctx *Context, worker *WorkerInfo, workerID string) {
	if atomic.LoadInt32(&ctx.FoundFlag) == 1 {
		worker.SendMu.Lock()
		_ = sendMsg(worker.Conn, map[string]any{"type": "stop"})
		worker.SendMu.Unlock()
		return
	}

	ctx.WorkersMu.Lock()
	var jobID int
	var chunkStart int64
	var chunkSize int
	reassigned := false
	if len(ctx.RemainingChunks) > 0 {
		rc := ctx.RemainingChunks[0]
		ctx.RemainingChunks = ctx.RemainingChunks[1:]
		jobID = rc.JobID
		chunkStart = rc.Start
		chunkSize = rc.Size
		reassigned = true
	} else {
		jobID = ctx.NextJobID
		ctx.NextJobID++
		chunkStart = ctx.NextChunkStart
		chunkSize = ctx.Settings.ChunkSize
		ctx.NextChunkStart += int64(chunkSize)
	}
	worker.CurrentJobID = jobID
	worker.CurrentChunkStart = chunkStart
	worker.CurrentChunkSize = chunkSize
	worker.LastCheckpoint = chunkStart
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
		"chunk_start":          chunkStart,
		"chunk_size":           chunkSize,
		"hb_interval":          ctx.Settings.HeartbeatInterval,
		"checkpoint_interval":  ctx.Settings.CheckpointInterval,
		"reassigned":           reassigned,
	}

	dispatchStart := time.Now()
	worker.SendMu.Lock()
	jobSendErr := sendMsg(worker.Conn, job)
	worker.SendMu.Unlock()
	if jobSendErr != nil {
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
ackLoop:
	for {
		select {
		case msg, ok := <-worker.IncomingMsgs:
			if !ok {
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
				log_heartbeat(worker, msg)
				select {
				case worker.HBAck <- struct{}{}:
				default:
				}
				continue
			}
			ack = msg
			break ackLoop
		case <-time.After(5 * time.Second):
			ctx.WorkersMu.Lock()
			delete(ctx.Workers, worker.ID)
			ctx.WorkersMu.Unlock()
			_ = worker.Conn.Close()
			if atomic.LoadInt32(&ctx.FoundFlag) == 0 {
				fmt.Printf("\nWORKER DISCONNECTED (WorkerID: %s) - no job ack\n", workerID)
			}
			return
		}
	}

	dispatchEnd := time.Now()
	lat := dispatchEnd.Sub(dispatchStart).Seconds()
	worker.DispatchLatency = &lat

	ackType := strFromAny(ack["type"])
	ackJobID := intFromAny(ack["job_id"])
	if ackType != "job_ack" || ackJobID != jobID {
		fmt.Printf("  WARNING: Unexpected ack from worker %s: %v\n", workerID, ack)
	}

	if reassigned {
		fmt.Printf("\nREASSIGNED JOB #%d (WorkerID: %s)\n", jobID, workerID)
	} else {
		fmt.Printf("\nDISPATCHED JOB #%d (WorkerID: %s)\n", jobID, workerID)
	}
	fmt.Printf("  Chunk: %d to %d\n", chunkStart, chunkStart+int64(chunkSize))
	fmt.Printf("  Dispatch Latency: %.2f milliseconds (C -> W)\n", lat*1000)
}

func report_result(ctx *Context) {
	passwordValue := ctx.FoundPassword

	totalAttempts := atomic.LoadInt64(&ctx.TotalAttempts)

	e2e := ctx.E2E

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
	for _, times := range ctx.ComputeTimes {
		workerSum := 0.0
		for _, v := range times {
			workerSum += v
		}
		if workerSum > totalComputeS {
			totalComputeS = workerSum
		}
	}
	ctx.WorkersMu.Unlock()

	overallHps := 0.0
	if e2e > 0 {
		overallHps = float64(totalAttempts) / e2e
	}

	if len(ctx.StoppedJobs) > 0 {
		fmt.Printf("\nJOBS STOPPED EARLY:\n")
		for _, sj := range ctx.StoppedJobs {
			fmt.Printf("  WorkerID: %s - %d attempts completed for Job #%d\n", sj.WorkerID, sj.Attempts, sj.JobID)
		}
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
	fmt.Printf("CHECKPOINT FREQUENCY: %d attempts\n", ctx.Settings.CheckpointInterval)
	fmt.Printf("CHECKPOINTS RECEIVED: %d\n", atomic.LoadInt64(&ctx.TotalCheckpoints))
	fmt.Printf("CRACKED BY: Worker #%s in Job #%d\n", ctx.FoundByWorker, ctx.FoundByJobID)
	fmt.Println(strings.Repeat("=", boxWidth))
}

func monitor_progress(ctx *Context) State {
	<-ctx.Done
	waitCh := make(chan struct{})
	go func() { ctx.WorkerWG.Wait(); close(waitCh) }()
	select {
	case <-waitCh:
	case <-time.After(5 * time.Second):
	}
	report_result(ctx)
	return StateCleanup
}

func error_state(ctx *Context) State {
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
		ComputeTimes: make(map[string][]float64),
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
		StateError:           error_state,
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
