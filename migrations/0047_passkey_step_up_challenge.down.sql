-- 残っている本人確認チャレンジを落としてから旧 CHECK へ戻す。
-- チャレンジは 5 分で失効する一時データなので、消してよい（消さないと制約を戻せない）。
DELETE FROM passkey_challenges WHERE challenge_type = 'step_up';

ALTER TABLE passkey_challenges DROP CONSTRAINT passkey_challenges_type_chk;

ALTER TABLE passkey_challenges
    ADD CONSTRAINT passkey_challenges_type_chk
        CHECK (challenge_type IN ('register', 'authenticate'));
