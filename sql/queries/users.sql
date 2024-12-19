-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email , password)
VALUES (
    gen_random_uuid() , NOW(),NOW() , $1 , $2
)
RETURNING id , created_at , updated_at , email , is_chirpy_red;

-- name: DeleteAllUsers :exec
DELETE  FROM users;

-- name: GetUserByEmail :one
SELEct * from users
where email = $1;

-- name: GetUserById :one
SELEct * from users
where id = $1;

-- name: UpdateUser :one
UPDATE users
SET password = $1 , email = $2 , updated_at = NOW()
where id = $3
RETURNING id , created_at , updated_at , email;


-- name: UpgradeUser :exec
UPDATE users 
SET is_chirpy_red = true
where id = $1;