CREATE TABLE IF NOT EXISTS orders
(
    id
    SERIAL
    PRIMARY
    KEY,
    ouid
    VARCHAR
(
    72
) NOT NULL UNIQUE,
    uuid VARCHAR
(
    72
) NOT NULL,
    pair VARCHAR
(
    72
) NOT NULL,
    matching_engine_id INTEGER,
    maker_fee DECIMAL NOT NULL,
    taker_fee DECIMAL NOT NULL,
    left_side_fraction DECIMAL NOT NULL,
    right_side_fraction DECIMAL NOT NULL,
    user_level VARCHAR
(
    20
) NOT NULL,
    direction VARCHAR
(
    20
) NOT NULL,
    match_constraint VARCHAR
(
    30
) NOT NULL,
    order_type VARCHAR
(
    30
) NOT NULL,
    price DECIMAL NOT NULL,
    quantity DECIMAL NOT NULL,
    filled_quantity DECIMAL NOT NULL,
    orig_price DECIMAL NOT NULL,
    orig_quantity DECIMAL NOT NULL,
    filled_orig_quantity DECIMAL NOT NULL,
    first_transfer_amount DECIMAL NOT NULL,
    remained_transfer_amount DECIMAL NOT NULL,
    status INTEGER NOT NULL,
    agent VARCHAR
(
    20
),
    ip VARCHAR
(
    11
),
    create_date TIMESTAMP NOT NULL
    );

CREATE TABLE IF NOT EXISTS fi_actions
(
    id
    SERIAL
    PRIMARY
    KEY,
    uuid
    VARCHAR
(
    72
) NOT NULL UNIQUE,
    parent_id INTEGER,
    event_type VARCHAR
(
    72
) NOT NULL,
    pointer VARCHAR
(
    72
) NOT NULL,
    symbol VARCHAR
(
    36
) NOT NULL,
    amount DECIMAL NOT NULL,
    sender VARCHAR
(
    36
) NOT NULL,
    sender_wallet_type VARCHAR
(
    36
) NOT NULL,
    receiver VARCHAR
(
    36
) NOT NULL,
    receiver_wallet_type VARCHAR
(
    36
) NOT NULL,
    agent VARCHAR
(
    20
),
    ip VARCHAR
(
    11
),
    create_date TIMESTAMP NOT NULL,
    status VARCHAR
(
    20
)
    );
CREATE INDEX IF NOT EXISTS idx_fi_actions_symbol ON fi_actions(symbol);
CREATE INDEX IF NOT EXISTS idx_fi_event_type ON fi_actions(event_type);
CREATE INDEX IF NOT EXISTS idx_fi_actions_status ON fi_actions(status);
CREATE INDEX IF NOT EXISTS idx_fi_actions_pointer ON fi_actions(pointer);

ALTER TABLE fi_actions
    ADD COLUMN IF NOT EXISTS category_name VARCHAR (36);

CREATE TABLE IF NOT EXISTS fi_action_retry
(
    id
    SERIAL
    PRIMARY
    KEY,
    fa_id
    INTEGER
    NOT
    NULL
    UNIQUE
    REFERENCES
    fi_actions
(
    id
),
    retries INTEGER NOT NULL DEFAULT 0,
    next_run_time TIMESTAMP NOT NULL,
    is_resolved BOOLEAN NOT NULL DEFAULT false,
    has_given_up BOOLEAN NOT NULL DEFAULT false
    );

CREATE TABLE IF NOT EXISTS fi_action_error
(
    id
    SERIAL
    PRIMARY
    KEY,
    fa_id
    INTEGER
    NOT
    NULL
    REFERENCES
    fi_actions
(
    id
),
    error TEXT NOT NULL,
    message TEXT NOT NULL,
    body TEXT,
    retry_id INTEGER REFERENCES fi_action_retry
(
    id
),
    date TIMESTAMP NOT NULL DEFAULT CURRENT_DATE
    );

CREATE TABLE IF NOT EXISTS pair_config
(
    pair VARCHAR
(
    72
) PRIMARY KEY,
    left_side_wallet_symbol VARCHAR
(
    36
) NOT NULL,
    right_side_wallet_symbol VARCHAR
(
    36
) NOT NULL,
    left_side_fraction DECIMAL NOT NULL,
    right_side_fraction DECIMAL NOT NULL,
    UNIQUE
(
    left_side_wallet_symbol,
    right_side_wallet_symbol
)
    );

CREATE TABLE IF NOT EXISTS user_level
(
    level VARCHAR
(
    36
) PRIMARY KEY
    );

CREATE TABLE IF NOT EXISTS pair_fee_config
(
    id
    SERIAL
    PRIMARY
    KEY,
    pair_config_id
    VARCHAR
(
    72
) NOT NULL REFERENCES pair_config
(
    pair
),
    direction VARCHAR
(
    36
) NOT NULL,
    user_level VARCHAR
(
    36
) NOT NULL REFERENCES user_level
(
    level
),
    maker_fee DECIMAL NOT NULL,
    taker_fee DECIMAL NOT NULL,
    UNIQUE
(
    direction,
    user_level,
    pair_config_id
)
    );

CREATE TABLE IF NOT EXISTS user_level_mapper
(
    id
    SERIAL
    PRIMARY
    KEY,
    uuid
    VARCHAR
(
    36
) NOT NULL UNIQUE,
    user_level VARCHAR
(
    36
) NOT NULL REFERENCES user_level
(
    level
)
    );

CREATE TABLE IF NOT EXISTS temp_events
(
    id
    SERIAL
    PRIMARY
    KEY,
    ouid
    VARCHAR
(
    72
) NOT NULL,
    event_type VARCHAR
(
    72
) NOT NULL,
    event_body TEXT NOT NULL,
    event_date TIMESTAMP NOT NULL
    );

COMMIT;
