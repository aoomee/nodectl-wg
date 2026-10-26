package wgrelay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const maxLog = 150000
const maxJobs = 50

var ErrBusy = errors.New("已有 WG 任务运行，请等待结束")
var ErrNotFound = errors.New("任务不存在")

type Job struct {
	ID       string     `json:"id"`
	Spec     Request    `json:"spec"`
	Status   string     `json:"status"`
	Created  time.Time  `json:"created"`
	Finished *time.Time `json:"finished,omitempty"`
	Log      string     `json:"log"`
	Result   *Result    `json:"result,omitempty"`
}
type Manager struct {
	mu      sync.Mutex
	root    string
	jobs    map[string]*Job
	active  string
	cancel  context.CancelFunc
	done    chan struct{}
	closed  bool
	execute Executor
	timeout time.Duration
}

func New(root string, execute Executor) (*Manager, error) {
	if execute == nil {
		execute = Execute
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	m := &Manager{root: root, jobs: make(map[string]*Job), execute: execute, timeout: time.Hour}
	for _, dir := range []string{root, filepath.Join(root, "jobs"), filepath.Join(root, "hosts")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
		if err := os.Chmod(dir, 0700); err != nil {
			return nil, err
		}
	}
	files, err := filepath.Glob(filepath.Join(root, "jobs", "*.json"))
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var j Job
		if err := json.Unmarshal(b, &j); err != nil {
			return nil, fmt.Errorf("WG 任务记录损坏：%s", filepath.Base(file))
		}
		if _, err := uuid.Parse(j.ID); err != nil || filepath.Base(file) != j.ID+".json" {
			return nil, errors.New("WG 任务标识无效")
		}
		j.Spec = j.Spec.Public()
		if j.Status == "running" || j.Status == "cancelling" {
			j.Status = "interrupted"
			j.Result = nil
			now := time.Now()
			j.Finished = &now
			j.Log += "\n面板进程中断，远端状态未确认。请检查服务器后重试。\n"
			if err := m.save(&j); err != nil {
				return nil, err
			}
		}
		if err := os.RemoveAll(filepath.Join(root, "jobs", j.ID)); err != nil {
			return nil, err
		}
		m.jobs[j.ID] = &j
	}
	return m, nil
}
func (m *Manager) save(j *Job) error {
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	file := filepath.Join(m.root, "jobs", j.ID+".json")
	if err = os.WriteFile(file+".tmp", b, 0600); err != nil {
		return err
	}
	return os.Rename(file+".tmp", file)
}
func clone(j *Job) Job {
	c := *j
	if j.Result != nil {
		r := *j.Result
		r.Diagnostics = append(json.RawMessage(nil), r.Diagnostics...)
		c.Result = &r
	}
	return c
}
func (m *Manager) List() []Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	jobs := make([]Job, 0, len(m.jobs))
	for _, j := range m.jobs {
		c := clone(j)
		c.Log = ""
		jobs = append(jobs, c)
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].Created.After(jobs[j].Created) })
	return jobs
}
func (m *Manager) Get(id string) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return Job{}, ErrNotFound
	}
	return clone(j), nil
}
func (m *Manager) Start(r Request) (Job, error) {
	if err := r.Validate(); err != nil {
		return Job{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return Job{}, errors.New("面板正在关闭")
	}
	if m.active != "" {
		return Job{}, ErrBusy
	}
	j := &Job{ID: uuid.NewString(), Spec: r.Public(), Status: "running", Created: time.Now()}
	if err := m.save(j); err != nil {
		return Job{}, err
	}
	// Retain the most recent 50 jobs; imported nodes have their own database records.
	for len(m.jobs) >= maxJobs {
		var oldest *Job
		for _, v := range m.jobs {
			if oldest == nil || v.Created.Before(oldest.Created) {
				oldest = v
			}
		}
		if err := os.Remove(filepath.Join(m.root, "jobs", oldest.ID+".json")); err != nil {
			break
		}
		delete(m.jobs, oldest.ID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	m.active = j.ID
	m.cancel = cancel
	m.done = make(chan struct{})
	m.jobs[j.ID] = j
	snapshot := clone(j)
	go m.run(ctx, cancel, j.ID, r, m.done)
	return snapshot, nil
}

type logWriter struct {
	m       *Manager
	id      string
	pending string
	secrets []string
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.m.mu.Lock()
	defer w.m.mu.Unlock()
	input := w.pending + string(p)
	w.pending = ""
	var clean strings.Builder
	for i := 0; i < len(input); {
		matched, partial := false, false
		for _, secret := range w.secrets {
			if strings.HasPrefix(input[i:], secret) {
				clean.WriteString("[密码已隐藏]")
				i += len(secret)
				matched = true
				break
			}
			if strings.HasPrefix(secret, input[i:]) {
				partial = true
				break
			}
		}
		if matched {
			continue
		}
		if partial {
			w.pending = input[i:]
			break
		}
		clean.WriteByte(input[i])
		i++
	}
	j := w.m.jobs[w.id]
	j.Log += clean.String()
	if len(j.Log) > maxLog {
		j.Log = j.Log[len(j.Log)-maxLog:]
	}

	return len(p), nil
}
func (m *Manager) run(ctx context.Context, cancel context.CancelFunc, id string, r Request, done chan struct{}) {
	defer close(done)
	defer cancel()
	folder := filepath.Join(m.root, "jobs", id)
	w := &logWriter{m: m, id: id, secrets: []string{r.APassword, r.BPassword}}
	// Redact longer secrets first when one is a substring of another.
	sort.Slice(w.secrets, func(i, j int) bool { return len(w.secrets[i]) > len(w.secrets[j]) })
	var result Result
	err := os.MkdirAll(folder, 0700)
	if err == nil {
		result, err = m.execute(ctx, r, folder, w)
	}
	if err == nil && (result.Kind != r.Mode || (r.Mode == "deploy" && !strings.HasPrefix(result.Link, "vless://"))) {
		err = errors.New("部署结果无效，未标记成功")
	}
	if err != nil {
		fmt.Fprintln(io.Writer(w), "\n未完成：", err)
	}
	cleanupErr := os.RemoveAll(folder)
	m.mu.Lock()
	defer m.mu.Unlock()
	j := m.jobs[id]
	if w.pending != "" {
		j.Log += "[隐藏]"
		w.pending = ""
	}
	j.Status = "succeeded"
	if err != nil {
		j.Status = "failed"
	}
	if ctx.Err() != nil {
		j.Status = "cancelled"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			j.Status = "timed_out"
		}
		j.Log += "\n任务已停止；远端可能保留服务，请检查后重试。\n"
	}
	if j.Status == "succeeded" {
		j.Result = &result
	}
	if cleanupErr != nil {
		j.Log += "\n临时工作目录清理失败，请检查面板数据目录。\n"
	}
	now := time.Now()
	j.Finished = &now
	if err := m.save(j); err != nil {
		j.Log += "\n结果保存失败，请立即复制结果并检查磁盘空间。\n"
	}
	m.active = ""
	m.cancel = nil
	w.pending = ""
	w.secrets = nil
}
func (m *Manager) Cancel(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.jobs[id]; !ok {
		return ErrNotFound
	}
	if m.active == id && m.cancel != nil {
		m.jobs[id].Status = "cancelling"
		m.cancel()
	}
	return nil
}
func (m *Manager) Close(ctx context.Context) {
	m.mu.Lock()
	m.closed = true
	done := m.done
	if m.cancel != nil {
		m.cancel()
	}
	m.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
		}
	}
}
