-- step-up の記録列を取り除く（記録は失われ、以後は最新のログイン時刻だけで新しさを測ることになる）。
ALTER TABLE sso_sessions DROP COLUMN step_up_at;
