package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"gorm.io/gorm"
)

// Transactions are carried in the context, every database access goes through dbFromContext.
// Although storing transactions in the context is not preferred, fosite handlers don't allow passing a transaction
// so we have to do it this way.

type txContextKey struct{}
type txRollbackHooksKey struct{}

type txRollbackHooks struct {
	mu         sync.Mutex
	finished   bool
	rolledBack bool
	hooks      []func(context.Context)
}

func contextWithTx(ctx context.Context, tx *gorm.DB) context.Context {
	return context.WithValue(ctx, txContextKey{}, tx)
}

func contextWithoutTx(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, txContextKey{}, nil)
	return context.WithValue(ctx, txRollbackHooksKey{}, nil)
}

func afterTxRollback(ctx context.Context, fn func(context.Context)) bool {
	hooks, ok := ctx.Value(txRollbackHooksKey{}).(*txRollbackHooks)
	if !ok || hooks == nil {
		return false
	}
	hooks.mu.Lock()
	if !hooks.finished {
		hooks.hooks = append(hooks.hooks, fn)
		hooks.mu.Unlock()
		return true
	}
	rolledBack := hooks.rolledBack
	hooks.mu.Unlock()
	if rolledBack {
		// The transaction already rolled back before a worker goroutine registered its hook, so run it immediately
		fn(contextWithoutTx(context.WithoutCancel(ctx)))
		return true
	}
	return false
}

func dbFromContext(ctx context.Context, fallback *gorm.DB) *gorm.DB {
	tx, ok := ctx.Value(txContextKey{}).(*gorm.DB)
	if ok && tx != nil {
		return tx.WithContext(ctx)
	}

	return fallback.WithContext(ctx)
}

// withTx runs fn inside a transaction, committing on nil error. Nested calls join the
// outer transaction.
func withTx(ctx context.Context, db *gorm.DB, fn func(ctx context.Context) error) error {
	if existing, ok := ctx.Value(txContextKey{}).(*gorm.DB); ok && existing != nil {
		return fn(ctx)
	}

	tx := db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return fmt.Errorf("error starting transaction: %w", tx.Error)
	}

	hooks := &txRollbackHooks{}
	var committed bool
	defer func() {
		if committed {
			hooks.mu.Lock()
			hooks.finished = true
			hooks.mu.Unlock()
			return
		}
		rErr := tx.Rollback().Error
		if rErr != nil && !errors.Is(rErr, gorm.ErrInvalidTransaction) {
			slog.ErrorContext(ctx, "Failed to rollback transaction", "error", rErr)
		}
		// Run rollback hooks only after the transaction has unwound and released all connections and locks
		hooks.mu.Lock()
		hooks.finished = true
		hooks.rolledBack = true
		pending := hooks.hooks
		hooks.hooks = nil
		hooks.mu.Unlock()
		cleanCtx := contextWithoutTx(context.WithoutCancel(ctx))
		for _, hook := range pending {
			hook(cleanCtx)
		}
	}()

	txCtx := context.WithValue(contextWithTx(ctx, tx), txRollbackHooksKey{}, hooks)
	err := fn(txCtx)
	if err != nil {
		return err
	}

	err = tx.Commit().Error
	if err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}
	committed = true

	return nil
}
