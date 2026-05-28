package trustscore

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Tier1Pipeline manages the async RoBERTa review pipeline.
type Tier1Pipeline struct {
	config   Tier1Config
	queue    QueueBackend
	audit    AuditBackend
	model    *RoBERTaClient
	feedback *FeedbackEngine
	redis    *redis.Client

	workers []*Tier1Worker
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.Mutex
}

// Tier1Worker processes jobs from the queue.
type Tier1Worker struct {
	id       string
	pipeline *Tier1Pipeline
}

// NewTier1Pipeline creates and initializes the pipeline.
func NewTier1Pipeline(config Tier1Config, redisClient *redis.Client) (*Tier1Pipeline, error) {
	audit, err := NewSQLiteAudit(config.AuditDBPath)
	if err != nil {
		return nil, fmt.Errorf("audit db: %w", err)
	}

	model := NewRoBERTaClient(config.ModelURL, config.ModelAPIKey)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := model.HealthCheck(ctx); err != nil {
		log.Printf("[WARN] RoBERTa health check failed (may start later): %v", err)
	}
	cancel()

	queue := NewRedisQueue(
		redisClient,
		config.RedisQueueKey,
		config.RedisFailedKey,
		config.RedisResultPrefix,
	)

	feedback := NewFeedbackEngine(config.CorrectionDelta, config.ConfidenceThreshold, audit)

	ctx, cancel = context.WithCancel(context.Background())

	return &Tier1Pipeline{
		config:   config,
		queue:    queue,
		audit:    audit,
		model:    model,
		feedback: feedback,
		redis:    redisClient,
		ctx:      ctx,
		cancel:   cancel,
	}, nil
}

// Start launches the worker pool.
func (p *Tier1Pipeline) Start() {
	for i := 0; i < p.config.WorkerCount; i++ {
		p.startWorker(i)
	}
	log.Printf("[INFO] Tier 1 pipeline started with %d workers", p.config.WorkerCount)
}

// startWorker creates and starts a single worker goroutine.
func (p *Tier1Pipeline) startWorker(index int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	worker := &Tier1Worker{
		id:       fmt.Sprintf("worker-%d", index),
		pipeline: p,
	}
	p.workers = append(p.workers, worker)
	p.wg.Add(1)
	go worker.run()
}

// Stop gracefully shuts down all workers.
func (p *Tier1Pipeline) Stop() {
	log.Printf("[INFO] Tier 1 pipeline stopping...")
	p.cancel()
	p.wg.Wait()

	if p.audit != nil {
		p.audit.Close()
	}

	log.Printf("[INFO] Tier 1 pipeline stopped")
}

// Enqueue adds a job to the queue for async processing.
func (p *Tier1Pipeline) Enqueue(job Tier1Job) error {
	if !p.config.Enabled {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := p.queue.Enqueue(ctx, job); err != nil {
		return err
	}

	go func() {
		if err := p.audit.LogEnqueue(job); err != nil {
			log.Printf("[ERROR] Tier1 audit log failed: %v", err)
		}
	}()

	return nil
}

// Enabled reports whether the pipeline is active.
func (p *Tier1Pipeline) Enabled() bool {
	return p.config.Enabled
}

// run is the main worker loop with panic recovery.
func (w *Tier1Worker) run() {
	defer w.pipeline.wg.Done()

	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[PANIC] Worker %s recovered: %v", w.id, rec)
		}
	}()

	for {
		select {
		case <-w.pipeline.ctx.Done():
			return
		default:
		}

		ctx, cancel := context.WithTimeout(w.pipeline.ctx, 5*time.Second)
		job, err := w.pipeline.queue.Dequeue(ctx, 5*time.Second)
		cancel()

		if err != nil {
			log.Printf("[ERROR] Worker %s dequeue error: %v", w.id, err)
			time.Sleep(time.Second)
			continue
		}

		if job == nil {
			continue
		}

		w.process(job)
	}
}

// process handles a single job with full error handling and retry logic.
func (w *Tier1Worker) process(job *Tier1Job) {
	log.Printf("[DEBUG] Worker %s processing job %s (tier: %s, prob: %.2f, retries: %d)",
		w.id, job.ID, job.Tier0Decision, job.LGBMProb, job.Retries)

	heartbeatCtx, heartbeatCancel := context.WithTimeout(context.Background(), 2*time.Second)
	w.pipeline.queue.SetHeartbeat(heartbeatCtx, w.id, job.ID, 60*time.Second)
	heartbeatCancel()

	ctx, cancel := context.WithTimeout(w.pipeline.ctx, 10*time.Second)
	result, err := w.pipeline.model.Predict(ctx, *job)
	cancel()

	var resultPtr *Tier1Result
	var errMsg string

	if err != nil {
		log.Printf("[ERROR] Worker %s RoBERTa failed for job %s: %v", w.id, job.ID, err)
		errMsg = err.Error()

		job.Retries++
		if job.Retries < w.pipeline.config.MaxRetries {
			log.Printf("[INFO] Worker %s requeueing job %s (retry %d/%d)",
				w.id, job.ID, job.Retries, w.pipeline.config.MaxRetries)

			requeueCtx, requeueCancel := context.WithTimeout(context.Background(), 2*time.Second)
			if requeueErr := w.pipeline.queue.Requeue(requeueCtx, *job); requeueErr != nil {
				log.Printf("[ERROR] Worker %s requeue failed: %v", w.id, requeueErr)
			} else {
				requeueCancel()
				w.clearHeartbeat()
				return
			}
			requeueCancel()
		}

		deadLetterCtx, deadLetterCancel := context.WithTimeout(context.Background(), 2*time.Second)
		if dlErr := w.pipeline.queue.MoveToFailed(deadLetterCtx, *job); dlErr != nil {
			log.Printf("[ERROR] Worker %s dead letter failed: %v", w.id, dlErr)
		}
		deadLetterCancel()

	} else {
		resultPtr = &Tier1Result{
			Label:         result.Label,
			Confidence:    result.Confidence,
			BenignProb:    result.BenignProb,
			MaliciousProb: result.MaliciousProb,
			ProcessedAt:   time.Now().Unix(),
			WorkerID:      w.id,
		}

		storeCtx, storeCancel := context.WithTimeout(context.Background(), 2*time.Second)
		if storeErr := w.pipeline.queue.StoreResult(storeCtx, job.ID, *resultPtr); storeErr != nil {
			log.Printf("[ERROR] Worker %s failed to store result: %v", w.id, storeErr)
		}
		storeCancel()

		if result.Confidence >= w.pipeline.config.ConfidenceThreshold {
			applied, delta, reason, feedbackErr := w.pipeline.feedback.Apply(*job, *result)
			if feedbackErr != nil {
				log.Printf("[ERROR] Worker %s feedback failed: %v", w.id, feedbackErr)
			} else if applied {
				log.Printf("[INFO] Worker %s applied feedback: %s delta=%.2f job=%s",
					w.id, reason, delta, job.ID)

				markCtx, markCancel := context.WithTimeout(context.Background(), 2*time.Second)
				w.pipeline.queue.MarkFeedbackApplied(markCtx, job.ID)
				markCancel()
			}
		}
	}

	var auditResult Tier1Result
	if resultPtr != nil {
		auditResult = *resultPtr
	}

	go func() {
		if auditErr := w.pipeline.audit.LogResult(job.ID, w.id, auditResult, errMsg); auditErr != nil {
			log.Printf("[ERROR] Worker %s audit log failed: %v", w.id, auditErr)
		}
	}()

	w.clearHeartbeat()
}

// clearHeartbeat removes the worker's processing indicator.
func (w *Tier1Worker) clearHeartbeat() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	w.pipeline.queue.DeleteHeartbeat(ctx, w.id)
	cancel()
}
