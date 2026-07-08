ALTER TABLE clients
    DROP COLUMN backchannel_logout_uri,
    DROP COLUMN frontchannel_logout_uri,
    DROP COLUMN post_logout_redirect_uris;
