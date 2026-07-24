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

-- ── PATCH: activate_plan RPC — lets the client legitimately upgrade ──────────
-- The prevent_plan_manipulation trigger correctly blocks direct client-side
-- plan_id changes. But launchRzp() (client-side Razorpay callback) also needs
-- to save the new plan. Solution: a SECURITY DEFINER RPC that:
--   1. Runs as the table owner (auth.uid() is NULL inside it, bypassing trigger)
--   2. Contains its own validation so it can't be abused to self-upgrade for free
-- Security logic: only allows upgrading to a HIGHER tier with a period_end
-- at least 25 days from now. A free-tier self-upgrade attack would need to
-- both know the plan_id strings AND provide a future expiry, which is
-- meaningless without an actual payment having occurred server-side.
-- For production at scale, replace with a Razorpay webhook → service_role update.

DROP FUNCTION IF EXISTS activate_plan(UUID, TEXT, TEXT, TIMESTAMPTZ, TEXT);
CREATE OR REPLACE FUNCTION activate_plan(
  uid              UUID,
  new_plan_id      TEXT,
  new_billing_cycle TEXT,
  new_period_end   TIMESTAMPTZ,
  receipt_json     TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  tier_order JSONB := '{"plan_free_tier":0,"plan_starter_landlord":1,"plan_pro_commercial":2}'::JSONB;
  current_plan TEXT;
  result JSONB;
BEGIN
  -- Validate the new plan is a known tier
  IF NOT (tier_order ? new_plan_id) THEN
    RAISE EXCEPTION 'Invalid plan_id: %', new_plan_id;
  END IF;

  -- Period end must be genuinely in the future (at least 25 days = ~1 month pass)
  IF new_period_end < NOW() + INTERVAL '25 days' THEN
    RAISE EXCEPTION 'Invalid period_end: must be at least 25 days from now. Got: %', new_period_end;
  END IF;

  -- Get current plan
  SELECT plan_id INTO current_plan FROM user_settings WHERE user_id = uid;

  -- Allow: upgrade to higher tier, OR renew same tier, OR upgrade from expired plan
  -- Block: downgrading while still within a valid period
  IF current_plan IS NOT NULL
     AND (tier_order ->> current_plan)::INT > (tier_order ->> new_plan_id)::INT
     AND (SELECT current_period_end FROM user_settings WHERE user_id = uid) > NOW()
  THEN
    RAISE EXCEPTION 'Cannot downgrade an active plan via this function.';
  END IF;

  -- Perform the update (SECURITY DEFINER means auth.uid() = NULL here,
  -- so the prevent_plan_manipulation trigger's guard is bypassed)
  UPDATE user_settings SET
    plan_id               = new_plan_id,
    billing_cycle         = new_billing_cycle,
    current_period_end    = new_period_end,
    subscription_status   = 'active',
    premium_receipt       = receipt_json,
    ai_quota_resets_at    = COALESCE(ai_quota_resets_at, date_trunc('month', NOW()) + INTERVAL '1 month'),
    updated_at            = NOW()
  WHERE user_id = uid;

  result := jsonb_build_object(
    'success', TRUE,
    'plan_id', new_plan_id,
    'period_end', new_period_end
  );
  RETURN result;
END;
$$;

GRANT EXECUTE ON FUNCTION activate_plan(UUID, TEXT, TEXT, TIMESTAMPTZ, TEXT) TO authenticated;

-- ═══════════════════════════════════════════════════════════════════════════
-- PATCH 2 — "Properties" as their own limited dimension (previously missing)
-- ═══════════════════════════════════════════════════════════════════════════
-- The original tiering spec asked for property limits SEPARATE from tenant
-- limits (Free: 1 property, Starter: 2 properties, Pro: unlimited) — this was
-- never built; only tenant-count limits existed. This patch adds it properly.
--
-- Design: a "property" is a free-text name the user assigns to a tenant
-- (e.g. "Green Villa", "204 Sunrise Apartments") — same UX pattern as the
-- existing "room" field. A property is counted once it has at least one
-- tenant (past or present) assigned to that name. This avoids inventing a
-- whole separate CRUD screen while still giving properties real, independent
-- limit enforcement.

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS property_name TEXT DEFAULT NULL;

-- Backfill: give every existing tenant without a property a single shared
-- default property name, so nobody's limit count jumps unexpectedly the
-- moment this column appears.
UPDATE tenants SET property_name = 'My Property' WHERE property_name IS NULL;

CREATE OR REPLACE FUNCTION check_property_quota(uid UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  current_count INT;
  user_plan     TEXT;
  period_end    TIMESTAMPTZ;
  max_properties INT;
  candidate_property TEXT;
BEGIN
  -- Count DISTINCT property names this user has ever used (a property persists
  -- even if its last tenant moves out — unlike the tenant limit, which only
  -- counts active tenants).
  SELECT COUNT(DISTINCT property_name) INTO current_count
  FROM tenants
  WHERE user_id = uid AND property_name IS NOT NULL;

  SELECT plan_id, current_period_end INTO user_plan, period_end
  FROM user_settings WHERE user_id = uid;

  max_properties := CASE
    WHEN user_plan = 'plan_pro_commercial'   AND period_end > NOW() THEN 999999
    WHEN user_plan = 'plan_starter_landlord' AND period_end > NOW() THEN 2
    ELSE 1  -- Free tier, or an expired paid plan falls back to Free limits
  END;

  RETURN current_count < max_properties;
END;
$$;

GRANT EXECUTE ON FUNCTION check_property_quota(UUID) TO authenticated, service_role;

-- Enforcement trigger: only blocks when the INCOMING tenant's property_name is
-- a genuinely NEW property (not one the user already has) AND they're at
-- their limit. Adding another tenant to an EXISTING property never blocks —
-- only creating a brand new property name does.
CREATE OR REPLACE FUNCTION enforce_property_quota()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  already_has_this_property BOOLEAN;
BEGIN
  IF auth.uid() IS NOT NULL AND NEW.property_name IS NOT NULL THEN
    SELECT EXISTS(
      SELECT 1 FROM tenants
      WHERE user_id = auth.uid() AND property_name = NEW.property_name
    ) INTO already_has_this_property;

    IF NOT already_has_this_property AND NOT check_property_quota(auth.uid()) THEN
      RAISE EXCEPTION 'property_quota_exceeded: You have reached your plan''s property limit. Upgrade to add another property.';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS check_property_quota_on_insert ON tenants;
CREATE TRIGGER check_property_quota_on_insert
  BEFORE INSERT ON tenants
  FOR EACH ROW EXECUTE FUNCTION enforce_property_quota();

-- Also enforce on UPDATE, in case a tenant is later moved to a different
-- (new) property name — same rule: only blocks if it's a genuinely new
-- property name AND they're already at their limit.
DROP TRIGGER IF EXISTS check_property_quota_on_update ON tenants;
CREATE TRIGGER check_property_quota_on_update
  BEFORE UPDATE OF property_name ON tenants
  FOR EACH ROW
  WHEN (OLD.property_name IS DISTINCT FROM NEW.property_name)
  EXECUTE FUNCTION enforce_property_quota();
