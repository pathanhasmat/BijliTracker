-- ═══════════════════════════════════════════════════════════════════════════
-- BijliTracker Pro — Full Database Security Setup v2
-- Run in: Supabase Dashboard → SQL Editor
-- Safe to re-run: all statements use IF NOT EXISTS / OR REPLACE guards
-- ═══════════════════════════════════════════════════════════════════════════

-- ── STEP 1: Enable RLS on all tables ────────────────────────────────────────
ALTER TABLE tenants           ENABLE ROW LEVEL SECURITY;
ALTER TABLE bills             ENABLE ROW LEVEL SECURITY;
ALTER TABLE payments          ENABLE ROW LEVEL SECURITY;
ALTER TABLE common_area_bills ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_settings     ENABLE ROW LEVEL SECURITY;

-- ── STEP 2: Drop old monolithic policies (clean slate) ─────────────────────
DROP POLICY IF EXISTS "tenants_iso"           ON tenants;
DROP POLICY IF EXISTS "bills_iso"             ON bills;
DROP POLICY IF EXISTS "payments_iso"          ON payments;
DROP POLICY IF EXISTS "common_area_bills_iso" ON common_area_bills;
DROP POLICY IF EXISTS "settings_iso"          ON user_settings;
DROP POLICY IF EXISTS "settings_select"       ON user_settings;
DROP POLICY IF EXISTS "settings_insert"       ON user_settings;
DROP POLICY IF EXISTS "settings_update"       ON user_settings;
DROP POLICY IF EXISTS "settings_update_safe"  ON user_settings;

-- ── STEP 3: Simple isolation policies for tenant/bill/payment tables ────────
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

-- ── STEP 4: SPLIT user_settings policies — CRITICAL SECURITY FIX ───────────
-- BEFORE: a single "FOR ALL ... USING (auth.uid() = user_id)" policy let any
-- authenticated user open the browser console and run:
--   supabase.from('user_settings').update({plan_id:'plan_pro_commercial'})
--     .eq('user_id', myOwnId)
-- ...and instantly upgrade themselves for free, since the policy only checked
-- WHO owns the row, never WHAT they changed on it.
--
-- AFTER: split into SELECT / INSERT / UPDATE. The UPDATE policy still allows
-- the row owner to write (Postgres RLS can't selectively allow some columns
-- and block others within one policy) — but the BEFORE UPDATE trigger in
-- Step 5 inspects the actual column-level diff and REJECTS the transaction
-- if plan_id, current_period_end, ai_quota_resets_at, or billing_cycle changed,
-- or if ai_assistant_queries_used moved by anything other than +1.

CREATE POLICY "settings_select"
  ON user_settings FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "settings_insert"
  ON user_settings FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "settings_update"
  ON user_settings FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Deliberately NO DELETE policy — users cannot delete their own settings row.

-- ── STEP 5: Trigger that blocks client-side plan/quota tampering ───────────
-- This is the real enforcement layer. RLS gets you row ownership; this trigger
-- gets you column-level integrity on the columns that control billing.
CREATE OR REPLACE FUNCTION prevent_plan_manipulation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  -- auth.uid() is NULL when the service_role key calls this (server-side requests
  -- from chat.js / launchRzp webhook), so server-side writes are never blocked.
  -- Only requests carrying an end-user JWT are restricted.
  IF auth.uid() IS NOT NULL THEN

    IF OLD.plan_id IS DISTINCT FROM NEW.plan_id THEN
      RAISE EXCEPTION 'SECURITY: plan_id cannot be modified by the client. Subscriptions are managed server-side only.';
    END IF;

    IF OLD.current_period_end IS DISTINCT FROM NEW.current_period_end THEN
      RAISE EXCEPTION 'SECURITY: current_period_end cannot be modified by the client.';
    END IF;

    IF OLD.ai_quota_resets_at IS DISTINCT FROM NEW.ai_quota_resets_at THEN
      RAISE EXCEPTION 'SECURITY: ai_quota_resets_at cannot be modified by the client.';
    END IF;

    IF OLD.billing_cycle IS DISTINCT FROM NEW.billing_cycle THEN
      RAISE EXCEPTION 'SECURITY: billing_cycle cannot be modified by the client.';
    END IF;

    -- ai_assistant_queries_used: allow only a +1 step (what the RPC does).
    -- Block decrements and block jumps of more than 1 in a single client UPDATE.
    IF NEW.ai_assistant_queries_used != OLD.ai_assistant_queries_used THEN
      IF NEW.ai_assistant_queries_used < OLD.ai_assistant_queries_used THEN
        RAISE EXCEPTION 'SECURITY: ai_assistant_queries_used cannot be decremented by the client.';
      END IF;
      IF (NEW.ai_assistant_queries_used - OLD.ai_assistant_queries_used) > 1 THEN
        RAISE EXCEPTION 'SECURITY: ai_assistant_queries_used can only increment by 1 per request.';
      END IF;
    END IF;

  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS enforce_plan_immutability ON user_settings;
CREATE TRIGGER enforce_plan_immutability
  BEFORE UPDATE ON user_settings
  FOR EACH ROW EXECUTE FUNCTION prevent_plan_manipulation();

-- ── STEP 6: Atomic AI-quota check-and-increment (fixes the race condition) ──
-- A plain "SELECT used, THEN UPDATE used+1" from chat.js has a window where
-- N concurrent requests can all read "4 of 5 used" and all proceed. This
-- function performs the check and the increment as ONE row-locked UPDATE,
-- so concurrent callers serialize against each other automatically.
CREATE OR REPLACE FUNCTION try_increment_ai_queries(uid UUID, query_limit INT)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  rows_updated INT;
BEGIN
  UPDATE user_settings
  SET ai_assistant_queries_used = ai_assistant_queries_used + 1
  WHERE user_id = uid
    AND ai_assistant_queries_used < query_limit;

  GET DIAGNOSTICS rows_updated = ROW_COUNT;
  RETURN rows_updated > 0;  -- TRUE = allowed & incremented, FALSE = quota exhausted
END;
$$;

-- Refund function — called by chat.js if the Groq call fails after pre-increment
CREATE OR REPLACE FUNCTION decrement_ai_queries(uid UUID)
RETURNS VOID
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  UPDATE user_settings
  SET ai_assistant_queries_used = GREATEST(0, ai_assistant_queries_used - 1)
  WHERE user_id = uid;
$$;

-- Legacy increment function — kept for backward compatibility with older chat.js deploys
CREATE OR REPLACE FUNCTION increment_ai_queries(uid UUID)
RETURNS VOID
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  UPDATE user_settings SET ai_assistant_queries_used = ai_assistant_queries_used + 1 WHERE user_id = uid;
$$;

REVOKE ALL ON FUNCTION try_increment_ai_queries(UUID, INT) FROM PUBLIC;
REVOKE ALL ON FUNCTION decrement_ai_queries(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION increment_ai_queries(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION try_increment_ai_queries(UUID, INT) TO service_role;
GRANT EXECUTE ON FUNCTION decrement_ai_queries(UUID) TO service_role;
GRANT EXECUTE ON FUNCTION increment_ai_queries(UUID) TO service_role;

-- ── STEP 7: Tenant-quota check function (value-based tiering) ───────────────
-- New tier spec: Free=2 tenants, Starter=10 tenants, Pro=unlimited.
-- Used both by the client (for an early UI check) and by the trigger below
-- (for the actual server-side enforcement that the client check can't bypass).
CREATE OR REPLACE FUNCTION check_tenant_quota(uid UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  current_count INT;
  user_plan     TEXT;
  period_end    TIMESTAMPTZ;
  max_tenants   INT;
BEGIN
  SELECT COUNT(*) INTO current_count
  FROM tenants
  WHERE user_id = uid AND move_out_date IS NULL;

  SELECT plan_id, current_period_end INTO user_plan, period_end
  FROM user_settings WHERE user_id = uid;

  max_tenants := CASE
    WHEN user_plan = 'plan_pro_commercial'   AND period_end > NOW() THEN 999999
    WHEN user_plan = 'plan_starter_landlord' AND period_end > NOW() THEN 10
    ELSE 2  -- Free tier, or an expired paid plan falls back to Free limits
  END;

  RETURN current_count < max_tenants;
END;
$$;

GRANT EXECUTE ON FUNCTION check_tenant_quota(UUID) TO authenticated, service_role;

-- ── STEP 8: Tenant-quota enforcement trigger ─────────────────────────────────
-- Blocks INSERT on tenants if the user is at/over their plan's limit — this is
-- what actually stops a client-side SDK call from bypassing the app's UI check.
CREATE OR REPLACE FUNCTION enforce_tenant_quota()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF auth.uid() IS NOT NULL THEN
    IF NOT check_tenant_quota(auth.uid()) THEN
      RAISE EXCEPTION 'tenant_quota_exceeded: You have reached your plan''s tenant limit. Upgrade to add more tenants.';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS check_tenant_quota_on_insert ON tenants;
CREATE TRIGGER check_tenant_quota_on_insert
  BEFORE INSERT ON tenants
  FOR EACH ROW EXECUTE FUNCTION enforce_tenant_quota();

-- ── STEP 9: New-user bootstrap trigger ───────────────────────────────────────
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO public.user_settings (
    user_id, rate_mode, fixed_rate, slabs, inv_lang, premium_receipt, display_name,
    plan_id, billing_cycle, subscription_status, current_period_end,
    ai_assistant_queries_used, ai_quota_resets_at,
    default_fixed_charge, default_tax_percent, updated_at
  ) VALUES (
    NEW.id, 'fixed', 0, '[]', 'both', '',
    COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name', ''),
    'plan_free_tier', 'monthly', 'active', NULL, 0,
    date_trunc('month', NOW()) + INTERVAL '1 month',
    0, 0, NOW()
  ) ON CONFLICT (user_id) DO NOTHING;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ── STEP 10: Columns for fixed base-charge + tax pass-through billing ───────
ALTER TABLE bills         ADD COLUMN IF NOT EXISTS fixed_charge         NUMERIC(10,2) DEFAULT 0;
ALTER TABLE bills         ADD COLUMN IF NOT EXISTS tax_percent          NUMERIC(5,2)  DEFAULT 0;
ALTER TABLE bills         ADD COLUMN IF NOT EXISTS tax_amount           NUMERIC(10,2) DEFAULT 0;
ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS default_fixed_charge NUMERIC(10,2) DEFAULT 0;
ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS default_tax_percent  NUMERIC(5,2)  DEFAULT 0;

-- ── STEP 11: Backfill settings rows for existing users missing them ─────────
INSERT INTO public.user_settings (
  user_id, rate_mode, fixed_rate, slabs, inv_lang, premium_receipt, display_name,
  plan_id, billing_cycle, subscription_status, current_period_end,
  ai_assistant_queries_used, ai_quota_resets_at,
  default_fixed_charge, default_tax_percent, updated_at
)
SELECT id, 'fixed', 0, '[]', 'both', '', '',
  'plan_free_tier', 'monthly', 'active', NULL, 0,
  date_trunc('month', NOW()) + INTERVAL '1 month', 0, 0, NOW()
FROM auth.users
WHERE id NOT IN (SELECT user_id FROM public.user_settings)
ON CONFLICT (user_id) DO NOTHING;

-- ── STEP 12: Verification ────────────────────────────────────────────────────
SELECT tablename, rowsecurity AS rls_enabled
FROM pg_tables
WHERE schemaname='public'
  AND tablename IN ('tenants','bills','payments','common_area_bills','user_settings')
ORDER BY tablename;
-- Expected: rls_enabled = true for all 5 rows

SELECT policyname, cmd FROM pg_policies WHERE tablename='user_settings' ORDER BY cmd;
-- Expected: 3 rows — INSERT, SELECT, UPDATE (no DELETE)

SELECT routine_name, security_type FROM information_schema.routines
WHERE routine_schema='public' AND routine_name IN (
  'try_increment_ai_queries','decrement_ai_queries','increment_ai_queries',
  'check_tenant_quota','enforce_tenant_quota','prevent_plan_manipulation','handle_new_user'
) ORDER BY routine_name;
-- Expected: 7 rows, all security_type = 'DEFINER'
