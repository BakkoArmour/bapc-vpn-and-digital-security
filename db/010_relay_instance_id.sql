SET search_path TO bapc_security_core;

-- Relays provisioned via AwsEc2RelayProvisioner need their AWS instance id
-- recorded so a later terminate call can find the right EC2 instance.
-- Nullable: manually-added relays (the only kind that existed before this)
-- have no AWS instance behind them at all.
ALTER TABLE relays ADD COLUMN instance_id text;
