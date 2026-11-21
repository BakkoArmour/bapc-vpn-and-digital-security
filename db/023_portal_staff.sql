SET search_path TO bapc_security_core;

-- Staff admin in the customer portal (/admin): a session remembers the bapc.app role it signed in with
-- ('user' or 'admin'; only 'admin' may open /admin, checked on the server for every request), and staff
-- actions are audited as actor 'staff' with the staff member's email in the detail.
ALTER TABLE portal_sessions ADD COLUMN role text NOT NULL DEFAULT 'user';
ALTER TABLE portal_audit DROP CONSTRAINT portal_audit_actor_check;
ALTER TABLE portal_audit ADD CONSTRAINT portal_audit_actor_check CHECK (actor IN ('customer','system','staff'));
CREATE INDEX portal_audit_signins_idx ON portal_audit(account_id, at DESC) WHERE action='auth.signed_in';
