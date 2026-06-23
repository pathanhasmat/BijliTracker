-- ═══════════════════════════════════════════════════════════════════════════
-- BijliTracker Pro — Supabase SQL Migration
-- Version: v9 → v10  (3-Tier SaaS Schema)
-- Run in: Supabase Dashboard → SQL Editor → Run
-- Safe to re-run: all statements use IF NOT EXISTS / IF EXISTS guards
-- ═══════════════════════════════════════════════════════════════════════════

-- ───────────────────────────────────────────────────────────────────────────
-- STEP 1 ▸ Add new subscription columns (idempotent)
-- ───────────────────────────────────────────────────────────────────────────
ALTER TABLE user_settings
  ADD COLUMN IF NOT EXISTS plan_id                  TEXT             DEFAULT 'plan_free_tier',
  ADD COLUMN IF NOT EXISTS billing_cycle            TEXT             DEFAULT 'monthly',
  ADD COLUMN IF NOT EXISTS subscription_status      TEXT             DEFAULT 'active',
  ADD COLUMN IF NOT EXISTS current_period_end       TIMESTAMPTZ      DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS ai_assistant_queries_used INTEGER         DEFAULT 0,
  ADD COLUMN IF NOT EXISTS display_name TEXT DEFAULT '',
  ADD COLUMN IF NOT EXISTS ai_quota_resets_at       TIMESTAMPTZ      DEFAULT NULL;

-- ───────────────────────────────────────────────────────────────────────────
-- STEP 2 ▸ Migrate existing rows from old schema to new columns
--           Runs only on rows that haven't been migrated yet (plan_id is
--           still the default value, so this is idempotent)
-- ───────────────────────────────────────────────────────────────────────────
UPDATE user_settings SET

  -- Map old tier text → new plan_id enum string
  plan_id = CASE
    WHEN COALESCE(tier, 'free') = 'starter' THEN 'plan_starter_landlord'
    WHEN COALESCE(tier, 'free') = 'pro'     THEN 'plan_pro_commercial'
    ELSE                                          'plan_free_tier'
  END,

  -- billing_cycle stays monthly (the old system was monthly-only)
  billing_cycle = 'monthly',

  -- Convert old premium_exp (JS epoch milliseconds stored as bigint) → TIMESTAMPTZ
  -- For free users (premium_exp = 0), leaves current_period_end as NULL
  current_period_end = CASE
    WHEN COALESCE(premium_exp, 0) > 0
    THEN to_timestamp(premium_exp / 1000.0) AT TIME ZONE 'UTC'
    ELSE NULL
  END,

  -- subscription_status: active if still within paid window, expired otherwise
  subscription_status = CASE
    WHEN COALESCE(premium_exp, 0) > 0
     AND to_timestamp(premium_exp / 1000.0) > NOW()
    THEN 'active'
    WHEN COALESCE(premium_exp, 0) > 0
    THEN 'expired'
    ELSE 'active'   -- free tier is always "active" (no subscription to expire)
  END,

  -- Carry over existing AI query counts (may be in either old or new column)
  ai_assistant_queries_used = COALESCE(ai_queries_used, 0),

  -- Set the first quota-reset date:
  --   • Paid users  → align with their subscription end date
  --   • Free users  → first day of next calendar month at midnight UTC
  ai_quota_resets_at = CASE
    WHEN COALESCE(premium_exp, 0) > 0
    THEN to_timestamp(premium_exp / 1000.0) AT TIME ZONE 'UTC'
    ELSE date_trunc('month', NOW()) + INTERVAL '1 month'
  END

-- Only migrate rows that still have the old default plan_id
WHERE plan_id = 'plan_free_tier'
  AND (
    -- Has an old-style premium_exp, meaning it genuinely needs migration
    COALESCE(premium_exp, 0) > 0
    OR COALESCE(tier, 'free') != 'free'
    OR ai_quota_resets_at IS NULL   -- catches free-tier rows that still need reset date
  );

-- For any remaining free-tier rows that somehow have NULL ai_quota_resets_at, fill them in
UPDATE user_settings
  SET ai_quota_resets_at = date_trunc('month', NOW()) + INTERVAL '1 month'
WHERE ai_quota_resets_at IS NULL;

-- ───────────────────────────────────────────────────────────────────────────
-- STEP 3 ▸ Atomic AI query counter function (called by chat.js Edge function)
--           SECURITY DEFINER so it runs with table-owner privileges regardless
--           of the caller's JWT — the RLS check is enforced in the function body
-- ───────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION increment_ai_queries(uid UUID)
RETURNS VOID
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  UPDATE user_settings
  SET ai_assistant_queries_used = ai_assistant_queries_used + 1
  WHERE user_id = uid;
$$;

-- Grant only the service role and authenticated users the right to call it
REVOKE ALL ON FUNCTION increment_ai_queries(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION increment_ai_queries(UUID) TO service_role;

-- ───────────────────────────────────────────────────────────────────────────
-- STEP 4 ▸ Monthly AI quota reset — pg_cron scheduled job
--           Runs daily at 02:00 UTC (07:30 IST) — checks every user's
--           individual ai_quota_resets_at date and resets whoever is due.
--           This honours per-user anniversary dates, not a shared calendar reset.
--
--           NOTE: pg_cron is enabled by default on Supabase paid projects.
--           On free projects, go to:
--           Database → Extensions → Search "pg_cron" → Enable
-- ───────────────────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Remove any stale version of this job before re-creating
SELECT cron.unschedule('bijlitracker-reset-ai-quotas') WHERE EXISTS (
  SELECT 1 FROM cron.job WHERE jobname = 'bijlitracker-reset-ai-quotas'
);

SELECT cron.schedule(
  'bijlitracker-reset-ai-quotas',
  '0 2 * * *',   -- 2:00 AM UTC every day (=7:30 AM IST)
  $$
    UPDATE public.user_settings
    SET
      ai_assistant_queries_used = 0,
      -- Advance reset date by the right interval for their billing cycle
      ai_quota_resets_at = ai_quota_resets_at + CASE
        WHEN billing_cycle = 'yearly'  THEN INTERVAL '1 year'
        WHEN plan_id = 'plan_free_tier' THEN INTERVAL '1 month'   -- calendar month for free
        ELSE                                 INTERVAL '1 month'   -- monthly subscription
      END
    WHERE
      ai_quota_resets_at IS NOT NULL
      AND ai_quota_resets_at <= NOW();
  $$
);

-- ───────────────────────────────────────────────────────────────────────────
-- STEP 5 ▸ Verify the migration — run this SELECT to confirm correctness
-- ───────────────────────────────────────────────────────────────────────────
SELECT
  COUNT(*)                                           AS total_users,
  COUNT(*) FILTER (WHERE plan_id = 'plan_free_tier')       AS free_users,
  COUNT(*) FILTER (WHERE plan_id = 'plan_starter_landlord') AS starter_users,
  COUNT(*) FILTER (WHERE plan_id = 'plan_pro_commercial')   AS pro_users,
  COUNT(*) FILTER (WHERE ai_quota_resets_at IS NULL)        AS missing_reset_date,
  COUNT(*) FILTER (WHERE current_period_end > NOW()
                     AND plan_id != 'plan_free_tier')       AS currently_paid_users
FROM user_settings;

-- ───────────────────────────────────────────────────────────────────────────
-- STEP 6 ▸ (OPTIONAL, run AFTER verifying Step 5 is correct)
--           Drop the old columns to keep the schema clean.
--           Comment this block out if you want to keep the old columns
--           for backward compatibility with older app versions.
-- ───────────────────────────────────────────────────────────────────────────
-- ALTER TABLE user_settings
--   DROP COLUMN IF EXISTS tier,
--   DROP COLUMN IF EXISTS premium_exp,
--   DROP COLUMN IF EXISTS ai_queries_used,
--   DROP COLUMN IF EXISTS ai_queries_month;

