// Business rules for the Principal Wallet (18th/36th-month maturity windows
// per deposit) and the Income Wallet (last-day-of-month withdrawals only).

function toDate(sqliteDatetime) {
  // sqlite datetime('now') strings look like "2026-01-15 10:22:31" (UTC).
  return new Date(String(sqliteDatetime).replace(' ', 'T') + 'Z');
}

function addMonths(date, n) {
  const d = new Date(date.getTime());
  d.setMonth(d.getMonth() + n);
  return d;
}

// Whole-calendar-month difference between two dates (ignores day-of-month),
// so a deposit approved anywhere in March is "18 months elapsed" for the
// entire calendar month of September the following year, etc.
function monthsBetween(from, to) {
  return (to.getFullYear() - from.getFullYear()) * 12 + (to.getMonth() - from.getMonth());
}

function isLastDayOfMonth(date) {
  const tomorrow = new Date(date.getFullYear(), date.getMonth(), date.getDate() + 1);
  return tomorrow.getDate() === 1;
}

function lastDayOfCurrentMonth(date) {
  return new Date(date.getFullYear(), date.getMonth() + 1, 0);
}

// Returns { eligibleNow, nextWindowDate, lots }
// lots = [{ deposit_id, available, monthsElapsed }] currently withdrawable.
// Pass bypassLock=true (admin testing-mode setting) to treat every approved
// deposit's remaining principal as eligible right now, regardless of the
// configured withdrawal windows — used so admins can test the withdrawal flow
// without waiting for a real eligibility window.
// windows: sorted array of month counts at which principal becomes eligible,
// e.g. [18, 36] (the default) or [1] for monthly, [3, 6] for quarterly+semi.
// This is read from the 'withdrawal_months' setting in the DB by the callers.
function getPrincipalEligibility(db, userId, now = new Date(), bypassLock = false, windows = [18, 36]) {
  const deposits = db.prepare(
    "SELECT * FROM deposits WHERE user_id = ? AND status = 'approved' ORDER BY id ASC"
  ).all(userId);

  // Ensure windows are sorted ascending for next-window calculation.
  const sortedWindows = [...windows].map(Number).filter(n => n > 0).sort((a, b) => a - b);
  if (sortedWindows.length === 0) sortedWindows.push(18, 36); // safety fallback

  let eligibleNow = 0;
  let nextWindowDate = null;
  const lots = [];

  for (const d of deposits) {
    const remaining = Number(d.amount) - Number(d.principal_withdrawn || 0);
    if (remaining <= 0.0000001) continue;

    const approvedAt = toDate(d.processed_at || d.created_at);
    const monthsElapsed = monthsBetween(approvedAt, now);

    if (bypassLock) {
      eligibleNow += remaining;
      lots.push({ deposit_id: d.id, available: remaining, monthsElapsed });
      continue;
    }

    if (sortedWindows.includes(monthsElapsed)) {
      // Current month is exactly one of the configured windows.
      eligibleNow += remaining;
      lots.push({ deposit_id: d.id, available: remaining, monthsElapsed });
    } else {
      // Find the next future window for this deposit.
      const nextWindow = sortedWindows.find(w => w > monthsElapsed);
      if (nextWindow !== undefined) {
        const windowStart = addMonths(approvedAt, nextWindow);
        if (!nextWindowDate || windowStart < nextWindowDate) nextWindowDate = windowStart;
      }
      // If monthsElapsed is past all windows with remaining balance, both
      // windows already passed for this lot — nothing further scheduled.
    }
  }

  return { eligibleNow, nextWindowDate, lots };
}

// Reserves `amount` of principal FIFO (oldest deposit first) across the
// currently-eligible lots, incrementing each deposit's principal_withdrawn.
// Returns the breakdown [{ deposit_id, amount }] to store with the
// withdrawal request (needed to roll back precisely if it's rejected).
function reservePrincipal(db, userId, amount, now = new Date(), bypassLock = false, windows = [18, 36]) {
  const { eligibleNow, lots } = getPrincipalEligibility(db, userId, now, bypassLock, windows);
  if (amount > eligibleNow + 0.0000001) {
    return { ok: false, eligibleNow };
  }

  let remainingNeeded = amount;
  const breakdown = [];
  const updateStmt = db.prepare('UPDATE deposits SET principal_withdrawn = principal_withdrawn + ? WHERE id = ?');

  for (const lot of lots) {
    if (remainingNeeded <= 0.0000001) break;
    const take = Math.min(lot.available, remainingNeeded);
    if (take <= 0) continue;
    updateStmt.run(take, lot.deposit_id);
    breakdown.push({ deposit_id: lot.deposit_id, amount: take });
    remainingNeeded -= take;
  }

  return { ok: true, breakdown };
}

// Rolls back a previously-reserved principal withdrawal (on rejection).
function releasePrincipal(db, breakdown) {
  if (!breakdown) return;
  const updateStmt = db.prepare('UPDATE deposits SET principal_withdrawn = principal_withdrawn - ? WHERE id = ?');
  for (const entry of breakdown) {
    updateStmt.run(entry.amount, entry.deposit_id);
  }
}

// Bulk Income Wallet % rule: a deposit approved on day 1-15 of the month
// earns the FULL admin-entered percentage; a deposit approved on day 16
// through the last day of the month earns HALF that percentage.
function bonusRateForDay(dayOfMonth, percentage) {
  return dayOfMonth <= 15 ? percentage : percentage / 2;
}

// 'YYYY-MM' key for a given date, used to tag which month a bulk % run
// covers and to prevent re-crediting the same deposit for the same month.
function monthKey(date) {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
}

module.exports = {
  toDate,
  addMonths,
  monthsBetween,
  isLastDayOfMonth,
  lastDayOfCurrentMonth,
  getPrincipalEligibility,
  reservePrincipal,
  releasePrincipal,
  bonusRateForDay,
  monthKey
};
