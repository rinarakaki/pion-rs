// https://github.com/pion/stun/blob/f00fc07896b44a2faa79d53db2b781fb54ed844c/agent.go

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// NoopHandler just discards any event.
pub fn noop_handler() -> Handler {
    |e: Event| None
}

impl Agent {
    /// NewAgent initializes and returns new Agent with provided handler.
    /// If h is nil, the NoopHandler will be used.
    pub fn new(h: Handler) -> Agent {
        let h = match h {
            Some(h) => h,
            None => noop_handler(),
        };
        let a = Agent {
            transactions: HashMap::new(),
            handler: h,
            ..Default::default()
        }
    
        a
    }
}

/// Agent is low-level abstraction over transaction list that
/// handles concurrency (all calls are goroutine-safe) and
/// time outs (via Collect call).
#[derive(Default)]
pub struct Agent {
    /// transactions is map of transactions that are currently
    /// in progress. Event handling is done in such way when
    /// transaction is unregistered before agentTransaction access,
    /// minimizing mux lock and protecting agentTransaction from
    /// data races via unexpected concurrent access.
    transactions: HashMap<TransactionID, AgentTransaction>,
    closed: bool, // all calls are invalid if true
    mux: sync::Mutex, // protects transactions and closed
    handler: Handler, // handles transactions
}

/// Handler handles state changes of transaction.
///
/// Handler is called on transaction state change.
/// Usage of e is valid only during call, user must
/// copy needed fields explicitly.
pub type Handler = Option<fn(Event)>;

/// Event is passed to Handler describing the transaction event.
/// Do not reuse outside Handler.
#[derive(Default)]
pub struct Event {
    pub transaction_id: [u8; TRANSACTION_ID_SIZE],
    pub message: Option<Message>,
    pub error: Error,
}

/// agentTransaction represents transaction in progress.
/// Concurrent access is invalid.
pub(crate) struct AgentTransaction {
    id: TransactionID,
    deadline: Instant,
}

var (
    // ErrTransactionStopped indicates that transaction was manually stopped.
    ErrTransactionStopped = errors.New("transaction is stopped")
    // ErrTransactionNotExists indicates that agent failed to find transaction.
    ErrTransactionNotExists = errors.New("transaction not exists")
    // ErrTransactionExists indicates that transaction with same id is already
    // registered.
    ErrTransactionExists = errors.New("transaction exists with same id")
)

impl Agent {
    /// StopWithError removes transaction from list and calls handler with
    /// provided error. Can return ErrTransactionNotExists and ErrAgentClosed.
    pub fn stop_with_error(
        &self,
        id: [u8; TRANSACTION_ID_SIZE],
        err: error,
    ) -> Result<(), error> {
        a.mux.Lock()
        if a.closed {
            a.mux.Unlock()
    
            return Err(ErrAgentClosed);
        }
        let t = self.transactions.remove(&id);
        let h = self.handler;
        a.mux.Unlock();
        match t {
            None => {
                return Err(ErrTransactionNotExists);
            },
            Some(t) => {
                h(Event {
                    transaction_id: t.id,
                    error: err,
                    ..Default::default()
                })
            }
        }
    
        Ok(())
    }

    /// Stop stops transaction by id with ErrTransactionStopped, blocking
    /// until handler returns.
    pub fn stop(&self, id: [u8; TRANSACTION_ID_SIZE]) -> Result<(), error> {
        self.stop_with_error(id, ErrTransactionStopped)
    }
}

/// ErrAgentClosed indicates that agent is in closed state and is unable
/// to handle transactions.
var ErrAgentClosed = errors.New("agent is closed")

impl Agent {
    /// Start registers transaction with provided id and deadline.
    /// Could return ErrAgentClosed, ErrTransactionExists.
    ///
    /// Agent handler is guaranteed to be eventually called.
    pub fn start(&self, id: [u8; TRANSACTION_ID_SIZE], deadline: Instant) -> Result<(), error> {
        a.mux.Lock()
        defer a.mux.Unlock()
        if self.closed {
            return Err(ErrAgentClosed);
        }
        let exists = self.transactions.contains_key(&id);
        if exists {
            return Err(ErrTransactionExists);
        }
        self.transactions.insert(id, AgentTransaction {
            id,
            deadline,
        });
    
        Ok(())
    }
}

/// agentCollectCap is initial capacity for Agent.Collect slices,
/// sufficient to make function zero-alloc in most cases.
const AGENT_COLLECT_CAP: usize = 100;

/// ErrTransactionTimeOut indicates that transaction has reached deadline.
var ErrTransactionTimeOut = errors.New("transaction is timed out")

impl Agent {
    /// Collect terminates all transactions that have deadline before provided
    /// time, blocking until all handlers will process ErrTransactionTimeOut.
    /// Will return ErrAgentClosed if agent is already closed.
    ///
    /// It is safe to call Collect concurrently but makes no sense.
    pub fn collect(&self, gc_time: Instant) -> Result<(), error> {
        let mut to_remove: Vec<TransactionId> = Vec::with_capacity(AGENT_COLLECT_CAP);
        a.mux.Lock()
        if self.closed {
            // Doing nothing if agent is closed.
            // All transactions should be already closed
            // during Close() call.
            a.mux.Unlock()
    
            return Err(ErrAgentClosed);
        }
        // Adding all transactions with deadline before gcTime
        // to toCall and toRemove slices.
        // No allocs if there are less than agentCollectCap
        // timed out transactions.
        for (id, t) in &self.transactions {
            if t.deadline < gc_time {
                to_remove.push(id);
            }
        }
        // Un-registering timed out transactions.
        for id in &to_remove {
            self.transactions.remove(id);
        }
        // Calling handler does not require locked mutex,
        // reducing lock time.
        let h = self.handler;
        a.mux.Unlock()
        // Sending ErrTransactionTimeOut to handler for all transactions,
        // blocking until last one.
        let mut event = Event {
            error: ErrTransactionTimeOut,
            ..Default::default()
        };
        for id in to_remove {
            event.transaction_id = id;
            h(event);
        }
    
        Ok(())
    }

    /// Process incoming message, synchronously passing it to handler.
    pub fn process(&self, m: Message) -> Result<(), error> {
        let event = Event {
            transaction_id: m.TransactionID,
            message: m,
        };
        a.mux.Lock()
        if a.closed {
            a.mux.Unlock()
    
            return Err(ErrAgentClosed);
        }
        let h = self.handler;
        delete(self.transactions, m.transaction_id)
        a.mux.Unlock()
        h(event);
    
        Ok(())
    }

    /// SetHandler sets agent handler to h.
    pub fn set_handler(&mut self, h: Handler) -> Result<(), error> {
        a.mux.Lock()
        if self.closed {
            a.mux.Unlock()
    
            return Err(ErrAgentClosed);
        }
        self.handler = h;
        a.mux.Unlock()
    
        Ok(())
    }

    /// Close terminates all transactions with ErrAgentClosed and renders Agent to
    /// closed state.
    pub fn close(&self) -> Result<(), error> {
        let mut e = Event {
            error: ErrAgentClosed,
            ..Default::default()
        }
        a.mux.Lock()
        if self.closed {
            a.mux.Unlock()
    
            return Err(ErrAgentClosed);
        }
        for id in &self.transactions.keys() {
            e.transaction_id = id;
            self.handler.unwrap()(e);
        }
        self.transactions = HashMap::new();
        self.closed = true;
        self.handler = None;
        a.mux.Unlock()
    
        Ok(())
    }
}

type TransactionID = [u8; TRANSACTION_ID_SIZE];
