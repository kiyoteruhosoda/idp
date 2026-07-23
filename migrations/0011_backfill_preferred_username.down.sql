-- up の逆操作: preferred_username が email と同値の行を NULL へ戻す（up は NULL を email で埋めたため）。
-- 明示的に email と同じ preferred_username を設定していた行も NULL になるが、既定値化前の状態へ戻す扱いとする。
UPDATE users
SET    preferred_username = NULL
WHERE  preferred_username = email;
