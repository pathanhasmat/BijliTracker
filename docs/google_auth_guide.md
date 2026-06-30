# BijliTracker Pro — Google OAuth Setup
## + Full Backend / Database System Audit
---

## PART A — BACKEND AUDIT RESULTS

### ✅ Things that are already correct

| Item | Status | Details |
|------|--------|---------|
| `doGoogleLogin()` in index.html | ✅ Ready | Calls `sb.auth.signInWithOAuth({provider:'google'})` with correct redirectTo |
| Hash fragment handler in `checkAuth()` | ✅ Ready | Waits 600ms then strips `#access_token=...` from URL after OAuth redirect |
| `onAuthStateChange` listener | ✅ Ready | Handles `SIGNED_IN`, `SIGNED_OUT`, `TOKEN_REFRESHED` correctly |
| Supabase client config | ✅ Ready | `persistSession:true`, `autoRefreshToken:true`, `storageKey:'bt_auth'` |
| JWT verification in chat.js | ✅ Ready | Uses `/auth/v1/user` endpoint to verify Google-issued JWTs exactly the same as email JWTs |
| `user_settings` RLS policy | ✅ Ready (in migration.sql) | `auth.uid()=user_id` isolates each user's settings |

### ❌ Issues Found — Must Fix Before Launch

**Issue 1: 4 tables have NO RLS policies**  
`tenants`, `bills`, `payments`, `common_area_bills` — these tables are missing Row Level Security policies. Without them, a logged-in user can currently read **all users' data** via the Supabase JS client. Fix: run db_rls_setup.sql (included below).

**Issue 2: New user's `user_settings` row is created on first save but has no initial row**  
A brand-new Google user has no `user_settings` row until they change a setting. `loadUserSettings()` handles this (PGRST116 = row not found is caught), but the `increment_ai_queries` RPC will silently fail (UPDATE finds no row) until the row exists. Fix: add an upsert on first login (included in db_rls_setup.sql below).

**Issue 3: `SUPABASE_ANON_KEY` not documented as a required Vercel env var**  
`chat.js` falls back to `SUPABASE_SERVICE_ROLE_KEY` for JWT verification if `SUPABASE_ANON_KEY` is missing, which works but uses a privileged key unnecessarily. Should be a separate env var.

**Issue 4: Service Worker caches `index.html` indefinitely**  
After you deploy a new version, returning users may get stale cached HTML. The SW uses `network-first` which is correct, but the `CACHE_NAME = 'bijlitracker-v1'` should be bumped each deploy. (Low urgency but will cause confusion during updates.)

**Issue 5: `redirectTo` in `doGoogleLogin` uses `window.location.href`**  
This is the full current URL including any path/query. On Vercel this is usually correct, but if a user tries to log in from a deep link (e.g. a shared URL), they get redirected to that deep link after auth instead of the app root. Minor UX issue — acceptable for now.

---

## PART B — GOOGLE AUTH SETUP (STEP BY STEP)

### PHASE 1: Google Cloud Console (~10 minutes)

**Step 1.1 — Create or open your Google Cloud project**

1. Open https://console.cloud.google.com in a browser
2. At the very top, click the project dropdown (next to "Google Cloud" logo)
3. Click **"New Project"**
   - Project name: `BijliTracker`
   - Click **"Create"**
   - Wait ~30 seconds, then select the new project from the dropdown

**Step 1.2 — Enable the OAuth API**

1. Click the hamburger menu (☰) → **"APIs & Services"** → **"Library"**
2. Search for **"Google Identity"**
3. Click **"Google Identity Toolkit API"** → click **"Enable"**

**Step 1.3 — Configure the OAuth Consent Screen** *(must do before creating credentials)*

1. Go to **"APIs & Services"** → **"OAuth consent screen"**
2. Choose **"External"** → click **"Create"**
3. Fill in these fields:
   - **App name**: `BijliTracker Pro`
   - **User support email**: your Gmail address
   - **Developer contact information**: your Gmail address
   - Leave everything else blank
4. Click **"Save and Continue"**
5. On the **Scopes** page — click **"Save and Continue"** (don't add scopes)
6. On the **Test users** page — click **"Save and Continue"**
7. On the Summary page — click **"Back to Dashboard"**
8. Click **"Publish App"** → **"Confirm"**
   *(This moves it from Testing to Production so any Google account can log in, not just test users)*

**Step 1.4 — Create OAuth 2.0 Credentials**

1. Go to **"APIs & Services"** → **"Credentials"**
2. Click **"+ Create Credentials"** → **"OAuth client ID"**
3. Application type: **"Web application"**
4. Name: `BijliTracker Web`
5. **STOP — you need the Supabase callback URL first.** Go to Step 2.1, get the URL, come back here.
6. Under **"Authorized redirect URIs"**, click **"+ Add URI"**  
   Paste the Supabase callback URL you got from Step 2.1
7. Under **"Authorized JavaScript origins"**, click **"+ Add URI"**  
   Add your production URL, e.g. `https://bijlitracker.vercel.app`  
   Also add `http://localhost:3000` for local development
8. Click **"Create"**
9. A popup shows your **Client ID** and **Client Secret**  
   → Copy both and keep them safe (you can also download the JSON)

---

### PHASE 2: Supabase Dashboard (~5 minutes)

**Step 2.1 — Get the Supabase callback URL**

1. Open https://supabase.com/dashboard
2. Click your project `mmnvbcztwjsdoyofjszx`
3. Go to **"Authentication"** (lock icon in left sidebar)
4. Click **"Providers"**
5. Find **"Google"** in the list — click it to expand
6. Copy the **"Callback URL"** shown at the top of the Google section.  
   It looks like:  
   `https://mmnvbcztwjsdoyofjszx.supabase.co/auth/v1/callback`  
   → This is what you paste as the "Authorized redirect URI" in Google (Step 1.4 Step 6)

**Step 2.2 — Enable Google Provider in Supabase**

1. In the same Google provider panel in Supabase:
2. Toggle **"Enable Sign in with Google"** → ON
3. Paste your **Client ID** from Google (Step 1.4 Step 9)
4. Paste your **Client Secret** from Google (Step 1.4 Step 9)
5. Click **"Save"**

**Step 2.3 — Add your site URL to Supabase allowed redirects**

1. Still in Supabase → Authentication
2. Click **"URL Configuration"** (in the left sub-menu)
3. Under **"Site URL"**: enter your Vercel production URL, e.g. `https://bijlitracker.vercel.app`
4. Under **"Redirect URLs"**: click **"Add URL"** and add:
   - `https://bijlitracker.vercel.app` (your production URL)
   - `http://localhost:3000` (for local dev)
   - `https://bijlitracker.vercel.app/**` (wildcard for all paths)
5. Click **"Save"**

---

### PHASE 3: Vercel Environment Variables (~3 minutes)

Go to your Vercel project → **Settings** → **Environment Variables** and add/verify:

| Variable Name | Value | Where to find it |
|---|---|---|
| `SUPABASE_URL` | `https://mmnvbcztwjsdoyofjszx.supabase.co` | Supabase → Settings → API |
| `SUPABASE_SERVICE_ROLE_KEY` | `eyJ...` (the service_role key) | Supabase → Settings → API → service_role |
| `SUPABASE_ANON_KEY` | `eyJ...` (the anon key) | Supabase → Settings → API → anon public |
| `GROQ_KEY_1` | `gsk_...` | console.groq.com → API Keys |
| `GROQ_KEY_2` to `GROQ_KEY_7` | `gsk_...` (optional, for rotation) | Same |

After adding, go to **Deployments** → click **"Redeploy"** on the latest deployment so the new env vars take effect.

---

### PHASE 4: Test the Flow (~5 minutes)

**Test 1 — Basic Google Sign-In**
1. Open your deployed app URL (or `localhost:3000`)
2. Click **"Continue with Google"**
3. A Google popup (or redirect) appears — sign in with your Google account
4. You should land back on the BijliTracker dashboard, logged in
5. Check: your Google profile name/email should appear in Settings

**Test 2 — Session persistence**
1. After logging in, close the tab completely
2. Reopen the app URL
3. You should still be logged in (no sign-in screen)

**Test 3 — Sign Out + Sign Back In**
1. Go to Settings → Sign Out
2. Click "Continue with Google" again
3. Because you already authorized the app, Google should sign you back in without prompting again

**Test 4 — AI Chat works after Google login**
1. Log in with Google
2. Go to Chat tab
3. Ask: "How many tenants do I have?"
4. You should get a valid response (not a 401 error)
   - If you get 401: the JWT from Google login isn't being passed correctly — check that `sb.auth.getSession()` returns a session after Google OAuth

**Test 5 — Data isolation (critical security test)**
1. Log in as User A (your Google account) → add a test tenant
2. Open an incognito window → log in as User B (different Google account)
3. User B's Tenants tab should be empty
4. User B should NOT be able to see User A's tenant
   - If they CAN see it: RLS is not set up on the tenants table → run db_rls_setup.sql immediately

---

### COMMON PROBLEMS & FIXES

**"redirect_uri_mismatch" error from Google**  
→ The URL in Google Console doesn't exactly match what Supabase sends.  
→ Fix: Copy the Supabase callback URL character-by-character into Google Console. No trailing slashes.

**Popup closes but nothing happens / stays on login screen**  
→ Your site URL or redirect URL isn't in Supabase's allowed list.  
→ Fix: Supabase → Authentication → URL Configuration → add your exact URL.

**"Error 400: redirect_uri_mismatch" on localhost**  
→ You forgot to add `http://localhost:3000` to both Google Console origins AND Supabase redirect URLs.

**User lands back on app but gets signed out immediately**  
→ `onAuthStateChange` fires `SIGNED_OUT` after `SIGNED_IN`. Usually means `loadAll()` threw an error (DB tables missing or no RLS). Check browser console.

**AI Chat returns 401 after Google login**  
→ `sb.auth.getSession()` might return null if the session wasn't persisted.  
→ Check: does `localStorage.getItem('bt_auth')` have a value? If not, the Supabase client `storageKey` may conflict with something clearing localStorage.

**New Google users see "AI quota exceeded" immediately**  
→ The `increment_ai_queries` RPC fails silently when `user_settings` row doesn't exist yet (UPDATE on non-existent row). Run `db_rls_setup.sql` which includes a trigger to auto-create the settings row on first Google login.

