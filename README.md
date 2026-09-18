# Suma FIN Services — Login, Register, Deposit, Withdraw

A minimal wallet-style web app with two roles only: **user** and **admin**.
No referral income, no genealogy/binary tree, no level income — just accounts,
deposits, and withdrawals.

## Structure
```
backend/    Node.js + Express API (uses Node's built-in sqlite module)
frontend/   Plain HTML/CSS/JS pages
```

## Features
- User registration & login (JWT-based auth)
- User dashboard: wallet balance, deposit history, withdrawal history
- **Deposits: USDT (BEP20) only.** The deposit page shows the platform's receiving
  address (set via `ADMIN_USDT_BEP20_ADDRESS` in `.env`); users enter the amount and
  transaction hash, then wait for admin approval.
- **Withdrawals: sent to the address saved on the user's profile.** Users must save a
  USDT (BEP20) address on their Profile page before they can withdraw — there's no
  free-text address field on the withdrawal form itself, so funds always go to the
  address on file. Funds are held immediately and refunded automatically if an admin
  rejects the request.
- **Profile page**: view account details, add/update the USDT (BEP20) withdrawal
  address, and change password (requires current password).
- Admin dashboard: totals, pending counts
- Admin can view/approve/reject deposits and withdrawals
- Admin can view all users and block/unblock accounts
- **Bulk % Income Wallet adjustment**: instead of editing one user's balance at a
  time, the admin enters a single percentage and a month. Deposits approved on
  the 1st-15th of that month earn the full percentage; deposits approved on the
  16th through the last day earn half. Each deposit is credited at most once per
  month, so previewing and re-running a month is always safe.
- **Admin password reset**: admin can set a new password for any user directly,
  no current password required.
- **Notifications**: admin has a Notifications page to broadcast a message to
  all users or target a single user; users see them on their own Notifications
  page with read/unread state.
- **Support**: users can open a support ticket and reply within its thread;
  admin has a Support page to view all tickets (open/resolved), reply, and
  mark them resolved.
- A first admin account is auto-seeded on server startup from `.env`

## Running locally (easiest way)

The backend also serves the frontend, so you only need to run one thing:

```bash
cd backend
npm install
cp .env.example .env      # then edit JWT_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_USDT_BEP20_ADDRESS
npm start                 # starts on http://localhost:5000
```

Then just open **http://localhost:5000** in Chrome (it redirects to the login
page). No Live Server extension, no separate frontend server, no CORS setup
needed — everything runs from this one server.

### Running the frontend separately (optional)
If you'd rather host the frontend files somewhere else (e.g. a static file
host, or VS Code's Live Server), open `login.html` from there and add this
line **before** the `js/api.js` script tag on every page:

```html
<script>window.API_BASE = 'https://your-backend-url.com/api';</script>
<script src="js/api.js"></script>
```

Opening the HTML files directly from disk (`file://...`) also works out of
the box, since `api.js` automatically falls back to `http://localhost:5000/api`
in that case.

## Default admin login
Whatever you set `ADMIN_EMAIL` / `ADMIN_PASSWORD` to in `.env` (defaults to
`admin@example.com` / `Admin@123` if left unset) — printed to the server
console on first run.

## Deploying (Railway, Render, etc.)

The backend serves the frontend itself, so **only `backend/` needs to be
deployed** — but this repo's root (`WalletApp/`) has both `backend/` and
`frontend/` folders and no `package.json` at the top, so a platform that
auto-detects Node apps by scanning the repo root (like Railway's Railpack)
won't find one there. Fix it one of two ways:

- **Set the service's Root Directory to `backend`** (Railway: Settings →
  Source → Root Directory). This is the simplest fix — the platform then
  scans `backend/`, finds its `package.json` (`"start": "node server.js"`),
  and builds/runs it normally.
- **Or leave Root Directory as the repo root** and use the `package.json`
  at `WalletApp/package.json`, which just delegates `install`/`start` into
  `backend/` for platforms that only look at the repo root.

Either way, set these environment variables on the platform (same ones as
`.env.example`): `JWT_SECRET`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`,
`ADMIN_USDT_BEP20_ADDRESS`. Don't set `PORT` — the platform provides it and
`server.js` already reads `process.env.PORT`. If you want the SQLite file to
survive redeploys, mount a persistent volume and point `DB_PATH` at a file
inside it.

## API summary
- `POST /api/auth/register` — {name, email, phone?, password, confirmPassword}
- `POST /api/auth/login` — {email, password}
- `GET  /api/user/me` — current user's profile + balances + deposit_address
- `PUT  /api/user/wallet-address` — {address} — save/update USDT (BEP20) withdrawal address
- `PUT  /api/user/password` — {currentPassword, newPassword, confirmNewPassword}
- `POST /api/user/deposits` — {amount, txn_ref}
- `GET  /api/user/deposits`
- `POST /api/user/withdrawals` — {amount} — sent to the saved wallet address
- `GET  /api/user/withdrawals`
- `GET  /api/admin/summary`
- `GET  /api/admin/users`
- `GET  /api/admin/users/:id`
- `PATCH /api/admin/users/:id/status` — {status: 'active'|'blocked'}
- `POST /api/admin/users/:id/reset-password` — {newPassword}
- `POST /api/admin/users/create-admin` — {name, email, password}
- `GET  /api/admin/deposits?status=pending`
- `PATCH /api/admin/deposits/:id` — {action: 'approve'|'reject', remarks?}
- `GET  /api/admin/withdrawals?status=pending`
- `PATCH /api/admin/withdrawals/:id` — {action: 'approve'|'reject', remarks?}
- `GET  /api/admin/bulk-adjustment/preview?percentage=5&month=2026-09` — dry run, no writes
- `POST /api/admin/bulk-adjustment/apply` — {percentage, month} — applies the % credit
- `GET  /api/admin/bulk-adjustment/history` — past bulk runs
- `GET  /api/admin/notifications` — everything sent so far
- `POST /api/admin/notifications` — {title, message, user_id?} — omit user_id to broadcast
- `GET  /api/admin/support?status=open` — list tickets
- `GET  /api/admin/support/:id` — ticket + message thread
- `POST /api/admin/support/:id/reply` — {message}
- `PATCH /api/admin/support/:id/status` — {status: 'open'|'resolved'}
- `GET  /api/user/notifications` — own + broadcast notifications with read state
- `GET  /api/user/notifications/unread-count`
- `POST /api/user/notifications/:id/read`
- `GET  /api/user/support` — own tickets
- `GET  /api/user/support/:id` — ticket + message thread
- `POST /api/user/support` — {subject, message} — opens a new ticket
- `POST /api/user/support/:id/reply` — {message}
