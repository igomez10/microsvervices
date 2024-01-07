CREATE DATABASE urlshortener;
-- SHORTLY
CREATE SEQUENCE IF NOT EXISTS urls_id_seq;
CREATE TABLE IF NOT EXISTS urls (
    id BIGINT NOT NULL PRIMARY KEY DEFAULT nextval('urls_id_seq'::regclass),
    url VARCHAR(10000) NOT NULL,
    alias VARCHAR(10) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL
);
CREATE INDEX IF NOT EXISTS urls_alias_idx ON urls (alias);
--  SEEDING DATA
INSERT INTO users (
        id,
        username,
        hashed_password,
        hashed_password_expires_at,
        salt,
        first_name,
        last_name,
        email,
        created_at,
        updated_at,
        deleted_at
    )
VALUES (
        1,
        'admin',
        'LPWJbW+u2por79jDW+uClI+VvxrX7HpT5eX53kdNd4U=',
        '2030-01-01 00:00:00',
        'MTUyNzJkYjgtZjVjNi00YjIxLTk3ZDktZDJkMTEzODM5NjQ1',
        'first_name',
        'last_name',
        'email@email.com',
        '2020-01-01 00:00:00',
        '2020-01-01 00:00:00',
        NULL
    );
ALTER SEQUENCE users_id_seq RESTART WITH 2;
INSERT INTO comments (
        id,
        content,
        like_count,
        created_at,
        user_id,
        deleted_at
    )
VALUES (
        1,
        'something',
        0,
        '2022-08-20 11:53:21.218349',
        1,
        NULL
    ),
    (
        1,
        'something',
        0,
        '2022-08-20 11:53:21.218349',
        1,
        NULL
    ),
    (
        2,
        'something',
        0,
        '2022-08-20 11:53:21.218349',
        1,
        NULL
    ),
    (
        3,
        'something',
        0,
        '2022-08-20 11:53:21.218349',
        1,
        NULL
    ),
    (
        4,
        'something',
        0,
        '2022-08-20 11:53:21.218349',
        2,
        NULL
    ),
    (
        5,
        'something',
        0,
        '2022-08-20 11:53:21.218349',
        2,
        NULL
    ),
    (
        6,
        'something',
        0,
        '2022-08-20 11:53:21.218349',
        2,
        NULL
    ),
    (
        7,
        'something',
        0,
        '2022-08-20 11:53:21.218349',
        2,
        NULL
    );
ALTER SEQUENCE comments_id_seq RESTART WITH 8;
INSERT INTO followers (follower_id, followed_id)
VALUES (1, 2);
ALTER SEQUENCE followers_id_seq RESTART WITH 2;
INSERT INTO roles (id, name, description, created_at, deleted_at)
VALUES (
        1,
        'administrator',
        'administrator',
        '2020-01-01 00:00:00',
        NULL
    ),
    (
        2,
        'user',
        'socialapp user',
        '2020-01-01 00:00:00',
        NULL
    );
ALTER SEQUENCE roles_id_seq RESTART WITH 3;
INSERT INTO scopes (id, name, description, created_at, deleted_at)
VALUES (
        1,
        'socialapp.users.list',
        'socialapp.users.list',
        '2020-01-01 00:00:00',
        NULL
    ),
    (
        2,
        'socialapp.users.create',
        'socialapp.users.create',
        '2020-01-01 00:00:00',
        NULL
    ),
    (
        3,
        'socialapp.users.update',
        'socialapp.users.update',
        '2020-01-01 00:00:00',
        NULL
    ),
    (
        4,
        'socialapp.users.delete',
        'socialapp.users.delete',
        '2020-01-01 00:00:00',
        NULL
    ),
    (
        5,
        'socialapp.comments.list',
        'socialapp.comments.list',
        '2020-01-01 00:00:00',
        NULL
    ),
    (
        6,
        'socialapp.comments.create',
        'socialapp.comments.create',
        '2020-01-01 00:00:00',
        NULL
    ),
    (
        7,
        'socialapp.comments.update',
        'socialapp.comments.update',
        '2020-01-01 00:00:00',
        NULL
    ),
    (
        8,
        'socialapp.comments.delete',
        'socialapp.comments.delete',
        '2020-01-01 00:00:00',
        NULL
    ),
    (
        9,
        'socialapp.followers.list',
        'socialapp.followers.list',
        '2020-01-01 00:00:00',
        NULL
    ),
    (
        10,
        'socialapp.following.list',
        'socialapp.following.list',
        '2020-01-01 00:00:00',
        NULL
    ),
    (
        11,
        'socialapp.users.read',
        'socialapp.users.read',
        '2022-09-28 20:07:31',
        NULL
    ),
    (
        12,
        'socialapp.follower.create',
        'socialapp.follower.create',
        '2022-09-28 20:13:04',
        NULL
    ),
    (
        13,
        'socialapp.follower.read',
        'socialapp.follower.read',
        '2022-09-28 20:14:03',
        NULL
    ),
    (
        14,
        'socialapp.follower.delete',
        'socialapp.follower.delete',
        '2022-09-28 20:14:55',
        NULL
    ),
    (
        15,
        'socialapp.feed.read',
        'socialapp.feed.read',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        16,
        'socialapp.roles.create',
        'socialapp.roles.create',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        17,
        'socialapp.roles.read',
        'socialapp.roles.read',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        18,
        'socialapp.roles.update',
        'socialapp.roles.update',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        19,
        'socialapp.roles.delete',
        'socialapp.roles.delete',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        20,
        'socialapp.roles.list',
        'socialapp.roles.list',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        21,
        'socialapp.scopes.list',
        'socialapp.scopes.list',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        22,
        'socialapp.scopes.read',
        'socialapp.scopes.read',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        23,
        'socialapp.scopes.create',
        'socialapp.scopes.create',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        24,
        'socialapp.scopes.delete',
        'socialapp.scopes.delete',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        25,
        'socialapp.scopes.update',
        'socialapp.scopes.update',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        26,
        'socialapp.roles.scopes.list',
        'socialapp.roles.scopes.list',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        27,
        'socialapp.roles.scopes.create',
        'socialapp.roles.scopes.create',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        28,
        'socialapp.roles.scopes.delete',
        'socialapp.roles.scopes.delete',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        29,
        'socialapp.roles.scopes.update',
        'socialapp.roles.scopes.update',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        30,
        'socialapp.roles.scopes.read',
        'socialapp.roles.scopes.read',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        31,
        'socialapp.users.scopes.list',
        'socialapp.users.scopes.list',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        32,
        'socialapp.users.scopes.create',
        'socialapp.users.scopes.create',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        33,
        'socialapp.users.scopes.delete',
        'socialapp.users.scopes.delete',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        34,
        'socialapp.users.scopes.update',
        'socialapp.users.scopes.update',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        35,
        'socialapp.users.scopes.read',
        'socialapp.users.scopes.read',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        36,
        'socialapp.users.roles.list',
        'socialapp.users.roles.list',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        37,
        'socialapp.users.roles.create',
        'socialapp.users.roles.create',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        38,
        'socialapp.users.roles.delete',
        'socialapp.users.roles.delete',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        39,
        'socialapp.users.roles.update',
        'socialapp.users.roles.update',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        40,
        'socialapp.users.roles.read',
        'socialapp.users.roles.read',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        41,
        'socialapp.roles.list_scopes',
        'socialapp.roles.list_scopes',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        42,
        'shortly.url.create',
        'Create a url',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        43,
        'shortly.url.update',
        'Update a url',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        44,
        'shortly.url.delete',
        'Delete a url',
        '2022-09-28 20:21:07',
        NULL
    ),
    (
        45,
        'socialapp.comments.read',
        'socialapp.comments.read',
        '2022-09-28 20:21:07',
        NULL
    );
ALTER SEQUENCE scopes_id_seq RESTART WITH 46;
INSERT INTO roles_to_scopes (id, role_id, scope_id)
VALUES (1, 1, 1),
    (2, 1, 2),
    (3, 1, 3),
    (4, 1, 4),
    (5, 1, 5),
    (6, 1, 6),
    (7, 1, 7),
    (8, 1, 8),
    (9, 1, 9),
    (10, 1, 10),
    (11, 1, 11),
    (12, 1, 12),
    (13, 1, 13),
    (14, 1, 14),
    (15, 1, 15),
    (16, 1, 16),
    (17, 1, 17),
    (18, 1, 18),
    (19, 1, 19),
    (20, 1, 20),
    (21, 1, 21),
    (22, 1, 22),
    (23, 1, 23),
    (24, 1, 24),
    (25, 1, 25),
    (26, 1, 26),
    (27, 1, 27),
    (28, 1, 28),
    (29, 1, 29),
    (30, 1, 30),
    (31, 1, 31),
    (32, 1, 32),
    (33, 1, 33),
    (34, 1, 34),
    (35, 1, 35),
    (36, 2, 1),
    (37, 2, 2),
    (38, 2, 3),
    (39, 2, 4),
    (40, 2, 5),
    (41, 2, 6),
    (42, 2, 7),
    (43, 2, 8),
    (44, 2, 9),
    (45, 2, 10),
    (46, 2, 11),
    (47, 2, 12),
    (48, 2, 13),
    (49, 2, 14),
    (50, 2, 15),
    (51, 2, 16),
    (52, 2, 17),
    (53, 2, 18),
    (54, 2, 19),
    (55, 2, 20),
    (56, 2, 21),
    (57, 2, 22),
    (58, 2, 23),
    (59, 2, 24),
    (60, 2, 25),
    (61, 2, 26),
    (62, 2, 27),
    (63, 2, 28),
    (64, 2, 29),
    (65, 2, 30),
    (66, 2, 31),
    (67, 2, 32),
    (68, 2, 33),
    (69, 2, 34),
    (70, 2, 35),
    (71, 1, 36),
    (72, 2, 36),
    (73, 1, 37),
    (74, 2, 37),
    (75, 1, 38),
    (76, 2, 38),
    (77, 1, 39),
    (78, 2, 39),
    (79, 1, 40),
    (80, 2, 40),
    (81, 1, 41),
    (82, 2, 41),
    (83, 1, 42),
    (84, 2, 42),
    (85, 1, 43),
    (86, 2, 43),
    (87, 1, 44),
    (88, 2, 44),
    (89, 1, 45),
    (90, 2, 45);
ALTER SEQUENCE roles_to_scopes_id_seq RESTART WITH 91;
INSERT INTO users_to_roles (id, role_id, user_id)
VALUES (1, 1, 1);
ALTER SEQUENCE users_to_roles_id_seq RESTART WITH 2;