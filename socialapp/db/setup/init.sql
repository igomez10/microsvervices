CREATE SEQUENCE IF NOT EXISTS users_id_seq;
CREATE TABLE IF NOT EXISTS users (
    id int4 NOT NULL PRIMARY KEY DEFAULT nextval('users_id_seq'::regclass),
    username VARCHAR(100) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL 
);

CREATE TABLE IF NOT EXISTS comments (
    id SERIAL NOT NULL,
    content VARCHAR(8192) NOT NULL,
    like_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    user_id INTEGER NOT NULL,
    CONSTRAINT fk_user_id
      FOREIGN KEY(user_id) 
	  REFERENCES users(id),

    deleted_at TIMESTAMP
);


CREATE SEQUENCE IF NOT EXISTS followers_id_seq;
CREATE TABLE "public"."followers" (
    "id" int4 NOT NULL DEFAULT nextval('followers_id_seq'::regclass),
    "follower_id" int4 NOT NULL,
    "followed_id" int4 NOT NULL,
    CONSTRAINT "followers_follower_id_fkey" FOREIGN KEY ("follower_id") REFERENCES "public"."users"("id"),
    CONSTRAINT "followers_followed_id_fkey" FOREIGN KEY ("followed_id") REFERENCES "public"."users"("id"),
    UNIQUE ("follower_id", "followed_id"),
    PRIMARY KEY ("id")
);


INSERT INTO "public"."users" ("id", "username", "first_name", "last_name", "email", "created_at", "deleted_at") VALUES
(1, 'igomez', 'first', 'last', 'first@last.com', '2022-08-20 11:50:28.522646', NULL),
(2, 'second', 'first', 'last', 'first@last.com', '2022-08-20 11:50:28.522646', NULL);

INSERT INTO "public"."comments" ("id", "content", "like_count", "created_at", "user_id", "deleted_at") VALUES
(1, 'something', 0, '2022-08-20 11:53:21.218349', 1, NULL),
(1, 'something', 0, '2022-08-20 11:53:21.218349', 1, NULL),
(2, 'something', 0, '2022-08-20 11:53:21.218349', 1, NULL),
(3, 'something', 0, '2022-08-20 11:53:21.218349', 1, NULL),
(4, 'something', 0, '2022-08-20 11:53:21.218349', 2, NULL),
(5, 'something', 0, '2022-08-20 11:53:21.218349', 2, NULL),
(6, 'something', 0, '2022-08-20 11:53:21.218349', 2, NULL),
(7, 'something', 0, '2022-08-20 11:53:21.218349', 2, NULL);
