# Relay fleet AMI

`POST /api/v1/relays/provision` (see `services/relay-fleet/`) boots relay
fleet nodes from a pre-baked "golden AMI" rather than installing anything at
boot time. That's deliberate: a relay's only job is proxying traffic, so
boot time and blast radius both matter more than for a general-purpose box —
cloning this repo and building it fresh on every launch would be slower,
needs outbound git/network access from a box that should otherwise need
almost none, and is a larger surface for something to go wrong while you're
trying to scale a fleet quickly.

This is the one-time manual step: bake the AMI once, then every `provision`
call just boots a copy of it.

## Baking the AMI

1. Launch a base EC2 instance (Ubuntu 22.04/24.04 LTS is assumed below; adapt
   package manager commands for a different distro).
2. Install Node.js 22:
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
   sudo apt-get install -y nodejs
   ```
3. Copy this repo's built `dist/` output (from `npm run build`) plus
   `package.json`/`package-lock.json`/`node_modules` (production deps only:
   `npm ci --omit=dev`) to e.g. `/opt/bapc`.
4. Install the systemd unit below as `/etc/systemd/system/bapc-relay.service`,
   then `sudo systemctl enable bapc-relay` (do **not** start it yet — the
   provisioner's UserData script writes `/etc/bapc/relay.env` and starts the
   service on first real boot; enabling now just means it will (re)start
   automatically after every future reboot too).
5. In the AWS Console (or CLI), create an image from this instance
   (EC2 → Instances → Actions → Image and templates → Create image). Note
   the resulting AMI id — that's `AWS_KMS_INTERMEDIATE_KEY_ID`'s sibling env
   var, `AWS_RELAY_AMI_ID` (see `.env.example`).

```ini
# /etc/systemd/system/bapc-relay.service
[Unit]
Description=BAPC Blind Relay
After=network.target

[Service]
EnvironmentFile=/etc/bapc/relay.env
ExecStart=/usr/bin/node /opt/bapc/dist/src/runtime/relay-server.js
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
```

## What the provisioner actually does at launch time

`services/relay-fleet/aws-ec2-relay-provisioner.ts`'s `UserData` script only
writes `/etc/bapc/relay.env` (just `RELAY_PORT`/`RELAY_BIND_HOST` today) and
runs `systemctl restart bapc-relay`. If that unit doesn't exist yet, the
instance's boot log will say so clearly rather than silently doing nothing —
that's the AMI not being baked yet, not a bug in the provisioner.

## Networking

The provisioner polls `DescribeInstances` for a public IP after launch, so
the subnet you provision into (`AWS_RELAY_SUBNET_ID`, optional) must have
auto-assign public IP enabled, and its security group
(`AWS_RELAY_SECURITY_GROUP_IDS`, optional) must allow inbound UDP on
`RELAY_PORT` (51900 by default) from wherever your mesh nodes actually
connect from.
