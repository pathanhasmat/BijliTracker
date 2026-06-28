-- ═══════════════════════════════════════════════════════════════════════════
-- BijliTracker Pro — Full Database Security Setup
-- Run this in Supabase SQL Editor BEFORE enabling Google Auth
-- (Also safe to run on an existing database — all statements are idempotent)
-- ═══════════════════════════════════════════════════════════════════════════

-- ── STEP 1: Verify your tables exist ────────────────────────────────────────
-- Run this SELECT first and check you see all 5 tables listed.
SELECT table_name 
FROM information_schema.tables 
WHERE table_schema = 'public' 
  AND table_name IN ('tenants','bills','payments','common_area_bills','user_settings')
ORDER BY table_name;

-- ── STEP 2: Enable RLS on every table ───────────────────────────────────────
-- Without RLS, ANY authenticated user can read ALL users' data via the Supabase
-- JS SDK. This is the most critical security fix.

ALTER TABLE tenants           ENABLE ROW LEVEL SECURITY;
ALTER TABLE bills             ENABLE ROW LEVEL SECURITY;
ALTER TABLE payments          ENABLE ROW LEVEL SECURITY;
ALTER TABLE common_area_bills ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_settings     ENABLE ROW LEVEL SECURITY;

-- ── STEP 3: Drop old policies (clean slate) ──────────────────────────────────
-- Safe to run even if the policies don't exist yet.

DROP POLICY IF EXISTS "tenants_iso"           ON tenants;
DROP POLICY IF EXISTS "bills_iso"             ON bills;
DROP POLICY IF EXISTS "payments_iso"          ON payments;
DROP POLICY IF EXISTS "common_area_bills_iso" ON common_area_bills;
DROP POLICY IF EXISTS "settings_iso"          ON user_settings;

-- ── STEP 4: Create isolation policies ───────────────────────────────────────
-- Each policy uses auth.uid() to match the user_id column.
-- "FOR ALL" covers SELECT, INSERT, UPDATE, DELETE in one policy.
-- "WITH CHECK" ensures users can only write their own user_id.

CREATE POLICY "tenants_iso"
  ON tenants FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "bills_iso"
  ON bills FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "payments_iso"
  ON payments FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "common_area_bills_iso"
  ON common_area_bills FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "settings_iso"
  ON user_settings FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- ── STEP 5: Service-role bypass for chat.js ─────────────────────────────────
-- The service role key used in chat.js bypasses RLS automatically in Supabase.
-- No additional policy needed for server-side reads/writes.
-- This comment is here to confirm that is intentional and correct.

-- ── STEP 6: Auto-create user_settings row on first login ────────────────────
-- Fixes the bug where new users (especially Google OAuth users) have no
-- user_settings row, causing increment_ai_queries() to silently fail
-- (UPDATE on non-existent row does nothing).
-- This function runs automatically whenever a new user signs up or logs in
-- for the first time via Google OAuth.

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.user_settings (
    user_id,
    rate_mode,
    fixed_rate,
    slabs,
    inv_lang,
    premium_receipt,
    plan_id,
    billing_cycle,
    subscription_status,
    current_period_end,
    ai_assistant_queries_used,
    ai_quota_resets_at,
    updated_at
  ) VALUES (
    NEW.id,
    'fixed',
    0,
    '[]',
    'both',
    '',
    'plan_free_tier',
    'monthly',
    'active',
    NULL,
    0,
    date_trunc('month', NOW()) + INTERVAL '1 month',  -- reset at start of next month
    NOW()
  )
  ON CONFLICT (user_id) DO NOTHING;  -- safe if row already exists
  RETURN NEW;
END;
$$;

-- Attach the trigger to auth.users (fires when a new user signs up)
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_user();

-- ── STEP 7: Verify RLS is active on all tables ───────────────────────────────
SELECT 
  schemaname,
  tablename,
  rowsecurity AS rls_enabled
FROM pg_tables
WHERE schemaname = 'public'
  AND tablename IN ('tenants','bills','payments','common_area_bills','user_settings')
ORDER BY tablename;
-- Expected: rls_enabled = true for ALL 5 rows

-- ── STEP 8: Verify policies exist ────────────────────────────────────────────
SELECT 
  tablename,
  policyname,
  cmd,
  qual
FROM pg_policies
WHERE schemaname = 'public'
  AND tablename IN ('tenants','bills','payments','common_area_bills','user_settings')
ORDER BY tablename;
-- Expected: 1 policy per table (5 total)

-- ── STEP 9: Verify the new-user trigger exists ───────────────────────────────
SELECT trigger_name, event_manipulation, event_object_table
FROM information_schema.triggers
WHERE trigger_name = 'on_auth_user_created';
-- Expected: 1 row

-- ── STEP 10: Verify increment_ai_queries RPC exists ──────────────────────────
SELECT routine_name, routine_type, security_type
FROM information_schema.routines
WHERE routine_schema = 'public'
  AND routine_name IN ('increment_ai_queries','handle_new_user');
-- Expected: 2 rows, both SECURITY DEFINER (security_type = 'DEFINER')

-- ── STEP 11: Backfill settings rows for any existing users missing them ───────
-- Run this ONCE to create settings rows for anyone who signed up before the
-- trigger was added. The trigger handles new users going forward.
INSERT INTO public.user_settings (
  user_id, rate_mode, fixed_rate, slabs, inv_lang, premium_receipt,
  plan_id, billing_cycle, subscription_status, current_period_end,
  ai_assistant_queries_used, ai_quota_resets_at, display_name, updated_at
)
SELECT 
  id,
  'fixed', 0, '[]', 'both', '',
  'plan_free_tier', 'monthly', 'active', NULL,
  0, date_trunc('month', NOW()) + INTERVAL '1 month', '', NOW()
FROM auth.users
WHERE id NOT IN (SELECT user_id FROM public.user_settings)
ON CONFLICT (user_id) DO NOTHING;

-- Count how many rows were backfilled:
SELECT COUNT(*) AS total_users,
       COUNT(*) FILTER (WHERE id IN (SELECT user_id FROM public.user_settings)) AS have_settings,
       COUNT(*) FILTER (WHERE id NOT IN (SELECT user_id FROM public.user_settings)) AS missing_settings
FROM auth.users;
-- Expected: missing_settings = 0 after backfill

