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
	"syscall"
	"time"
)

type State int

const (
	StateParseArgs State = iota
	StateHandleArgs
	StateParseShadow
	StateListen
	StateWaitRegister
	StateReceiveRegistration
	StateDispatchJob
	StateWaitResult
	StateCleanup
	StateError
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

type Context struct {
	Settings    Settings
	ExitMessage string

	PwInfo PasswordInfo

	ServerLn   net.Listener
	WorkerConn net.Conn
	WorkerAddr string

	WorkerID string
	JobID    int

	ParseStart *time.Time
	ParseEnd   *time.Time
	ParseTime  *float64

	RuntimeStart *time.Time
	RuntimeEnd   *time.Time
	Runtime      *float64

	DispatchLatency     *float64
	ResultReturnLatency *float64
}

type Handler func(*Context) State

func parseArguments(ctx *Context) State {
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

func handleArguments(ctx *Context) State {
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

func parseShadow(ctx *Context) State {
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
	return StateWaitRegister
}

func acceptWorker(ctx *Context) State {
	if ctx.ServerLn == nil {
		ctx.ExitMessage = "ERROR: Control server failed to start."
		return StateError
	}

	conn, err := ctx.ServerLn.Accept()
	if err != nil {
		ctx.ExitMessage = fmt.Sprintf("ERROR: Worker connection attempt failed. %v", err)
		return StateError
	}

	ctx.WorkerConn = conn
	ctx.WorkerAddr = conn.RemoteAddr().String()

	fmt.Printf("\nWORKER CONNECTED FROM: %s\n", ctx.WorkerAddr)
	return StateReceiveRegistration
}

func receiveRegistration(ctx *Context) State {
	if ctx.WorkerConn == nil {
		ctx.ExitMessage = "ERROR: No worker socket"
		return StateError
	}

	fmt.Println("  Waiting for worker to send registration request...")

	registrationReq, err := recvWithTimeout(ctx.WorkerConn, 5*time.Second)
	if err != nil {
		ctx.ExitMessage = fmt.Sprintf("ERROR: Worker failed to register. %v", err)
		return StateWaitRegister
	}

	fmt.Println("  Worker registration request received")

	if typ, _ := registrationReq["type"].(string); typ != "register" {
		_ = sendMsg(ctx.WorkerConn, map[string]any{
			"type":   "registration_err",
			"reason": "bad register",
		})
		return StateError
	}

	workerID, _ := registrationReq["worker_id"].(string)
	ctx.WorkerID = workerID

	_ = sendMsg(ctx.WorkerConn, map[string]any{"type": "registration_ok"})
	fmt.Printf("  Worker registered successfully (%s)\n", ctx.WorkerID)
	return StateDispatchJob
}

func dispatchJob(ctx *Context) State {
	now := time.Now()
	ctx.RuntimeStart = &now

	charset := "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"0123456789" +
		"@#%^&*()_+-=.,:;?"

	if ctx.WorkerConn == nil {
		ctx.ExitMessage = "No connected worker"
		return StateError
	}

	job := map[string]any{
		"type":        "job",
		"job_id":      ctx.JobID,
		"username":    ctx.Settings.Username,
		"alg_id":      ctx.PwInfo.AlgID,
		"salt":        ctx.PwInfo.Salt,
		"hash":        ctx.PwInfo.Hash,
		"hash_full":   ctx.PwInfo.Full,
		"charset":     charset,
		"hb_interval": ctx.Settings.HeartbeatInterval,
	}

	dispatchStart := time.Now()
	if err := sendMsg(ctx.WorkerConn, job); err != nil {
		ctx.ExitMessage = fmt.Sprintf("ERROR: Dispatch of job to worker failed. %v", err)
		return StateError
	}

	ack, err := recvMsg(ctx.WorkerConn)
	if err != nil {
		ctx.ExitMessage = fmt.Sprintf("ERROR: Dispatch of job to worker failed. %v", err)
		return StateError
	}

	typ, _ := ack["type"].(string)
	jobID := intFromAny(ack["job_id"])
	if typ != "job_ack" || jobID != ctx.JobID {
		ctx.ExitMessage = fmt.Sprintf("ERROR: Expected job_ack, got: %v", ack)
		return StateError
	}

	dispatchEnd := time.Now()
	lat := dispatchEnd.Sub(dispatchStart).Seconds()
	ctx.DispatchLatency = &lat

	fmt.Printf("\nDISPATCHED JOB #%d (Worker: %s)\n", ctx.JobID, ctx.WorkerID)
	fmt.Printf("  Dispatch Latency: %.2f milliseconds (C -> W)\n", lat*1000)
	return StateWaitResult
}

func waitResult(ctx *Context) State {
	fmt.Println("  Waiting for worker to finish cracking...")

	if ctx.WorkerConn == nil {
		ctx.ExitMessage = "ERROR: Failed to receive result. no worker connection"
		return StateError
	}

	heartbeatSec := ctx.Settings.HeartbeatInterval
	heartbeatDur := time.Duration(heartbeatSec) * time.Second

	missed := 0
	maxMisses := 1

	for {
		// Wait for a message (heartbeat or final result)
		msg, err := recvWithTimeout(ctx.WorkerConn, heartbeatDur)
		if err != nil {
			// Timeout in current interval
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				missed++
				if missed > maxMisses {
					ctx.ExitMessage = fmt.Sprintf("ERROR: Worker unresponsive (no message for %d seconds)", heartbeatSec*(missed))
					return StateError
				}
				fmt.Printf("  No message from worker in last %d sec (miss %d). Waiting again.\n", heartbeatSec, missed)
				continue
			}
			// Error
			ctx.ExitMessage = fmt.Sprintf("ERROR: Failed to receive message from worker. %v", err)
			return StateError
		}

		// Got message
		missed = 0

		typ := strFromAny(msg["type"])

		// Final result
		if typ == "result" {
			_ = sendMsg(ctx.WorkerConn, map[string]any{"type": "result_ack"})
			latMsg, err := recvMsg(ctx.WorkerConn)
			if err != nil {
				ctx.ExitMessage = fmt.Sprintf("ERROR: Failed to receive result latency message. %v", err)
				return StateError
			}
			rrl := floatFromAny(latMsg["result_return_latency"])
			ctx.ResultReturnLatency = &rrl

			result := msg

			fmt.Println("\n" + strings.Repeat("=", 40))
			fmt.Println("            CRACKING RESULTS")
			fmt.Println(strings.Repeat("=", 40))

			found := boolFromAny(result["found"])
			var statusValue string
			var passwordValue string
			if found {
				statusValue = "SUCCESS"
				passwordValue, _ = result["password"].(string)
			} else {
				statusValue = "FAILED"
				passwordValue = "N/A"
			}

			attempts := floatFromAny(result["attempts"])
			crackTime := floatFromAny(result["compute_time"])

			hps := 0.0
			if crackTime > 0 {
				hps = attempts / crackTime
			}

			end := time.Now()
			ctx.RuntimeEnd = &end
			runtime := end.Sub(*ctx.RuntimeStart).Seconds()
			ctx.Runtime = &runtime

			labelWidth := 20
			fmt.Printf("%-*s %s\n", labelWidth, "STATUS:", statusValue)
			fmt.Printf("%-*s %s\n", labelWidth, "PASSWORD:", passwordValue)
			fmt.Printf("%-*s %.0f\n", labelWidth, "ATTEMPTS:", attempts)
			fmt.Printf("%-*s %.2f seconds\n", labelWidth, "TIME:", crackTime)
			fmt.Printf("%-*s %.2f hashes/sec\n", labelWidth, "SPEED:", hps)

			parseMs := 0.0
			if ctx.ParseTime != nil {
				parseMs = (*ctx.ParseTime) * 1000
			}
			dispatchMs := 0.0
			if ctx.DispatchLatency != nil {
				dispatchMs = (*ctx.DispatchLatency) * 1000
			}
			resultMs := 0.0
			if ctx.ResultReturnLatency != nil {
				resultMs = (*ctx.ResultReturnLatency) * 1000
			}

			fmt.Printf("%-*s %.2f milliseconds\n", labelWidth, "PARSING TIME:", parseMs)
			fmt.Printf("%-*s %.2f milliseconds\n", labelWidth, "DISPATCH LATENCY:", dispatchMs)
			fmt.Printf("%-*s %.2f milliseconds\n", labelWidth, "RESULT LATENCY:", resultMs)
			fmt.Printf("%-*s %.2f seconds\n", labelWidth, "E2E RUNTIME:", runtime)
			fmt.Println(strings.Repeat("=", 40))

			return StateCleanup
		}

		// heartbeat push from worker (push-based)
		if typ == "heartbeat_resp" {
			delta := floatFromAny(msg["delta_tested"])
			total := floatFromAny(msg["total_tested"])
			threadsActive := intFromAny(msg["threads_active"])
			rate := floatFromAny(msg["current_rate"])
			fmt.Printf("\nHEARTBEAT (every %d sec)\n", heartbeatSec)
			fmt.Printf("  Delta Tested: %.0f\n", delta)
			fmt.Printf("  Total Attempts: %.0f\n", total)
			fmt.Printf("  Threads Active: %d\n", threadsActive)
			fmt.Printf("  Current Rate): %.2f hashes/sec\n", rate)

			// keep waiting for next message (worker will push again after interval)
			continue
		}

		// unexpected message: log and continue
		fmt.Printf("  Received unexpected message while waiting")
	}
}

func controllerError(ctx *Context) State {
	fmt.Printf("\n%s\n", ctx.ExitMessage)
	return StateCleanup
}

func cleanup(ctx *Context) State {
	if ctx.WorkerConn != nil {
		_ = ctx.WorkerConn.Close()
	}
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
		JobID: 1,
	}

	handlers := map[State]Handler{
		StateParseArgs:           parseArguments,
		StateHandleArgs:          handleArguments,
		StateParseShadow:         parseShadow,
		StateListen:              listen,
		StateWaitRegister:        acceptWorker,
		StateReceiveRegistration: receiveRegistration,
		StateDispatchJob:         dispatchJob,
		StateWaitResult:          waitResult,
		StateError:               controllerError,
		StateCleanup:             cleanup,
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
