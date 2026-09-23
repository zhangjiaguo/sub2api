package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// openaiTicketGrabRepository 打票（turn-state 采集）数据访问：当前票据 + 打票日志。
// 纯 SQL 实现（表由 migrations/240 创建，不经 ent schema）。
type openaiTicketGrabRepository struct{ db *sql.DB }

// NewOpenAITicketGrabRepository 构造打票仓库。
func NewOpenAITicketGrabRepository(db *sql.DB) service.OpenAITicketGrabRepository {
	return &openaiTicketGrabRepository{db: db}
}

func (r *openaiTicketGrabRepository) GetTicket(ctx context.Context, accountID int64) (*service.OpenAITicket, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT account_id, value, state_length, blocks, issued_at, expires_at,
		       exit_ip, exit_colo, fingerprint, model, plan_type, used_percent,
		       http_status, duration_ms, updated_at
		FROM openai_codex_tickets WHERE account_id = $1`, accountID)
	var t service.OpenAITicket
	if err := row.Scan(&t.AccountID, &t.Value, &t.StateLength, &t.Blocks, &t.IssuedAt, &t.ExpiresAt,
		&t.ExitIP, &t.ExitColo, &t.Fingerprint, &t.Model, &t.PlanType, &t.UsedPercent,
		&t.HTTPStatus, &t.DurationMS, &t.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get ticket: %w", err)
	}
	return &t, nil
}

func (r *openaiTicketGrabRepository) UpsertTicket(ctx context.Context, t *service.OpenAITicket) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO openai_codex_tickets (
			account_id, value, state_length, blocks, issued_at, expires_at,
			exit_ip, exit_colo, fingerprint, model, plan_type, used_percent,
			http_status, duration_ms, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NOW())
		ON CONFLICT (account_id) DO UPDATE SET
			value = EXCLUDED.value,
			state_length = EXCLUDED.state_length,
			blocks = EXCLUDED.blocks,
			issued_at = EXCLUDED.issued_at,
			expires_at = EXCLUDED.expires_at,
			exit_ip = EXCLUDED.exit_ip,
			exit_colo = EXCLUDED.exit_colo,
			fingerprint = EXCLUDED.fingerprint,
			model = EXCLUDED.model,
			plan_type = EXCLUDED.plan_type,
			used_percent = EXCLUDED.used_percent,
			http_status = EXCLUDED.http_status,
			duration_ms = EXCLUDED.duration_ms,
			updated_at = NOW()`,
		t.AccountID, t.Value, t.StateLength, t.Blocks, t.IssuedAt, t.ExpiresAt,
		t.ExitIP, t.ExitColo, t.Fingerprint, t.Model, t.PlanType, t.UsedPercent,
		t.HTTPStatus, t.DurationMS)
	if err != nil {
		return fmt.Errorf("upsert ticket: %w", err)
	}
	return nil
}

func (r *openaiTicketGrabRepository) InsertGrabLog(ctx context.Context, log *service.OpenAITicketGrabLog) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO openai_codex_ticket_grab_logs (
			account_id, result, http_status, state_length, blocks, exit_ip, exit_colo, detail, duration_ms
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		log.AccountID, log.Result, log.HTTPStatus, log.StateLength, log.Blocks,
		log.ExitIP, log.ExitColo, log.Detail, log.DurationMS)
	if err != nil {
		return fmt.Errorf("insert grab log: %w", err)
	}
	return nil
}

func (r *openaiTicketGrabRepository) ListGrabLogs(ctx context.Context, accountID int64, limit, offset int) ([]*service.OpenAITicketGrabLog, error) {
	args := []any{limit, offset}
	query := `
		SELECT id, account_id, result, http_status, state_length, blocks, exit_ip, exit_colo, detail, duration_ms, created_at
		FROM openai_codex_ticket_grab_logs`
	if accountID > 0 {
		query += ` WHERE account_id = $3`
		args = append(args, accountID)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2`
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list grab logs: %w", err)
	}
	defer rows.Close()
	var logs []*service.OpenAITicketGrabLog
	for rows.Next() {
		var l service.OpenAITicketGrabLog
		if err := rows.Scan(&l.ID, &l.AccountID, &l.Result, &l.HTTPStatus, &l.StateLength, &l.Blocks,
			&l.ExitIP, &l.ExitColo, &l.Detail, &l.DurationMS, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan grab log: %w", err)
		}
		logs = append(logs, &l)
	}
	return logs, rows.Err()
}

// AccountGrabStats 窗口内打票统计：成功率（采到合法封装票据）与有效率（符合期望长度/块数）。
func (r *openaiTicketGrabRepository) AccountGrabStats(ctx context.Context, accountIDs []int64, window time.Duration) (map[int64]*service.OpenAITicketGrabStats, error) {
	if len(accountIDs) == 0 {
		return map[int64]*service.OpenAITicketGrabStats{}, nil
	}
	placeholders := make([]string, len(accountIDs))
	args := make([]any, 0, len(accountIDs)+1)
	args = append(args, time.Now().Add(-window))
	for i, id := range accountIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, id)
	}
	// 成功 = accepted（符合期望形态）+ shape_mismatch（采到票据但形态不符）：
	// 两者都意味着上游确实铸造了 turn-state。
	query := fmt.Sprintf(`
		SELECT account_id,
		       COUNT(*) AS total,
		       COUNT(*) FILTER (WHERE result IN ('accepted','shape_mismatch')) AS success,
		       COUNT(*) FILTER (WHERE result = 'accepted') AS valid
		FROM openai_codex_ticket_grab_logs
		WHERE created_at >= $1 AND account_id IN (%s)
		GROUP BY account_id`, strings.Join(placeholders, ","))
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("account grab stats: %w", err)
	}
	defer rows.Close()
	stats := make(map[int64]*service.OpenAITicketGrabStats, len(accountIDs))
	for rows.Next() {
		var (
			accountID             int64
			total, success, valid int64
		)
		if err := rows.Scan(&accountID, &total, &success, &valid); err != nil {
			return nil, fmt.Errorf("scan grab stats: %w", err)
		}
		stats[accountID] = &service.OpenAITicketGrabStats{
			Total:   total,
			Success: success,
			Valid:   valid,
		}
	}
	return stats, rows.Err()
}
