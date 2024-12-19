-- name: InsertRefreshToken :one
INSERT into refresh_tokens (token , user_id , expires_at)
VALUES ($1,$2,$3)
RETURNING *;



-- name: GetRefreshToken :one
Select * from refresh_tokens where token = $1;

-- name: RevokeToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW() , updated_at = NOW()
where token = $1;