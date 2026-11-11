# IKEv2 experiment workflow

This directory supports Section 5, the derived packet-size Table 1, the
captured IKE overhead Table 2, and the multi-region latency evaluation reported
as Table 4/Figure 6.

Reference-data replay does not require privileges. During the conference AE
period, packet capture and the multi-region rerun may use disposable,
preconfigured ECS nodes supplied by the authors. Assigned evaluators receive
time-limited credentials, sudo access, and node/route mappings privately
through the conference AE portal. Those machines and secrets are intentionally
absent from the permanent public artifact. After AE, users must provide their
own hosts and administrator access for a fresh network rerun.

## Fast evaluator workflow

Run from the repository root:

```bash
python3 experiment/scripts/analyze_latency.py --check-paper-values
python3 experiment/scripts/calculate_packet_sizes.py --check-paper-values
python3 -m pip install matplotlib
python3 experiment/scripts/generate_plots.py
```

The first command reconstructs the latency summary underlying Table 4/Figure 6
from the numeric arrays in `reference_results/latency/`. `network_summary.csv`
records requested loop counts, successful samples, and the UF/DR/DF/HF counts.

### Analyze latency JSON

With no JSON argument, `analyze_latency.py` summarizes every distributed
reference result:

```bash
python3 experiment/scripts/analyze_latency.py
```

Add `--check-paper-values` to verify that the rounded statistics match Table 4:

```bash
python3 experiment/scripts/analyze_latency.py --check-paper-values
```

The script can also summarize one JSON file produced by
`parse_latency_log.py`. It automatically obtains the link and scheme from a
name such as `route-a-emlkem768.json` or `a-emlkem768.json`:

```bash
python3 experiment/scripts/analyze_latency.py \
  experiment/local/route-a-emlkem768.json
```

For other filenames, explicitly supply the paper link and scheme. For example,
if `emlkem_bj_kr.json` represents link `a` and eMLKEM-768:

```bash
python3 experiment/scripts/analyze_latency.py \
  experiment/local/emlkem_bj_kr.json --link a --scheme emlkem768
```

Use `--check-paper-values` with a single file only when intentionally comparing
that fresh run with the corresponding paper row. The recognized paper scheme
names are `ecp384`, `emlkem768`, `mlkem1024`, and `emlkem1024`; not every
scheme is available on every link.

Output columns are the successful sample count (`n`), minimum, maximum, 99th
percentile, median, and arithmetic mean latency in milliseconds. The final
`UF/DR/DF/HF` field reports UDP failures, decryption retries, decryption
failures, and total handshake failures. Legacy reference arrays that do not
embed failure counters display `n/a` where appropriate.

One reference ECDH file for route (a) contains 10,001 successful samples even
though the requested loop count was 10,000. The source log contained one
successful pre-loop session; the paper statistics, and therefore this replay,
include it. On route (d), successful sample counts are below 1,000 because
failed handshakes have no establishment duration. ML-KEM-1024 was unreachable
on route (c), so it has no latency array.

### Packet size calculation from pk/ct sizes

The packet-size script first verifies the Table 2 field-breakdown totals, then
reconstructs Table 1 from each KEM public-key/ciphertext size plus the measured
fixed IKE_SA_INIT overhead (208 bytes in the initiator request and 241 bytes in
the responder response). Reported spare space excludes the 48-byte IPv6+UDP
headers, exactly as in the paper.

## IPv6 Nodes Preparation

### Temporary author-provided ECS access (conference AE only)

The public artifact explains every command but contains no login material.
The authors maintain a separate private access handoff and upload it only
through the confidential AE website. It records:

- access window, username/authentication method, and SSH fingerprints;
- each ECS region, SSH endpoint, public experiment IPv6, and instance shape;
- the route (a)-(d) node mapping;
- installed artifact path, proposal state, certificate expiry, and reset steps.

Evaluators are therefore not expected to create or pay for globally
distributed nodes. The dedicated `ae` account has sudo access on these
disposable hosts, so evaluators may use the supplied state, change proposals,
capture traffic, restart services, or rebuild the artifact if desired.

The ECS service is not part of the permanent Zenodo deposit and will be
withdrawn after the stated AE and review window. Access is limited to these
test instances and does not grant access to any author production system.

### Permanent public artifact (after AE)

The permanent package provides all source code, templates, commands, and
anonymized reference measurements, but it does not provide hosted machines,
endpoint addresses, SSH credentials, certificates, raw logs, or packet
captures. A later user performing a fresh network run must provision comparable
IPv6 Linux hosts, obtain administrator access, build/install strongSwan, and
generate disposable certificates as described below. Reference-data replay
remains fully available without root access or ECS resources.

## Complete network rerun

### Warning

Use only the temporary AE ECS instances or other dedicated Ubuntu 22.04 IPv6
hosts you administer. Installation and deployment write below `/usr` and
`/etc`, start or stop `charon`, and install IPsec policies that can break the
current SSH route. Keep console access or a separate management interface.
Do not use the included research KEM for production traffic.

### 1. Access or rebuild both endpoints

The temporary AE nodes should already contain the artifact and dependencies.
Evaluators may use sudo to audit or rebuild them. Users of the permanent
archive should run the same steps on their own machines. From a clean node,
install:

```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev libgmp-dev \
  libsystemd-dev libcurl4-openssl-dev pkg-config bison flex autoconf \
  automake libtool gperf iproute2 iputils-ping tcpdump tshark python3
```

Copy the artifact to both hosts, then build:

```bash
bash experiment/scripts/build_strongswan.sh
sudo make -C strongswan_6.0.4 install
```

The first command automatically runs `prepare_strongswan.sh`. That script
clones the official strongSwan repository when needed, verifies commit
`6856bfe` (2026-03-04), and overlays the files from
`strongswan_6.0.4_inc/`. The incremental files add the `mlex` plugin plus the
bounded retry documented in `../MODIFICATIONS_SUMMARY.md`. To prepare without
building, run:

```bash
bash experiment/scripts/prepare_strongswan.sh
```

### 2. Generate disposable authentication material

Generate credentials once, on a trusted evaluation host:

```bash
bash experiment/scripts/generate_test_certs.sh
```

Securely copy only the necessary files:

- responder: `caCert.pem`, `serverCert.pem`, `serverKey.pem`
- initiator: `caCert.pem`, `clientCert.pem`, `clientKey.pem`

Place CA certificates in `/etc/swanctl/x509ca/`, endpoint certificates in
`/etc/swanctl/x509/`, and endpoint private keys in
`/etc/swanctl/private/` with mode 0600. Do not commit generated credentials;
`experiment/local/` is ignored by Git.

### 3. Instantiate configuration templates

Install the daemon configuration by copying the supplied file to
`/etc/strongswan.conf`:

```bash
sudo cp experiment/config/strongswan.conf /etc/strongswan.conf
```

Replace every `@...@` placeholder in the appropriate swanctl template, then
install it as `/etc/swanctl/swanctl.conf`:

```bash
sudo mkdir -p /etc/swanctl
sudo cp experiment/config/initiator-swanctl.conf /etc/swanctl/swanctl.conf
# Use responder-swanctl.conf instead on the responder.
```

To generate all four experiment configurations from a template in one step,
run the following from the repository root. With `init`, provide the responder
IPv6 address; with `resp`, provide the responder's own IPv6 address:

```bash
bash experiment/scripts/generate_swanctl_configs.sh init 2001:db8::2
bash experiment/scripts/generate_swanctl_configs.sh resp 2001:db8::2
```

Each invocation writes four files under `experiment/config/`, named with the
role and proposal (for example,
`initiator-aes192-sha256-emlkem768.swanctl.conf`). Copy the desired generated
file to `/etc/swanctl/swanctl.conf` on the matching endpoint.

If the files are updated later, copy the changed files over the installed
versions again and reload the swanctl configuration before testing:

```bash
sudo swanctl --load-all
```

Restart the daemon as well when changing daemon-level settings in
`/etc/strongswan.conf`; `--load-all` reloads swanctl objects but does not
restart `charon`.

### 4. Start daemon and get ready for the connection tests

Start and load the daemon according to the host's installation method. For a
manual non-systemd build this is typically:

```bash
sudo /usr/libexec/ipsec/charon &
sudo swanctl --load-all
sudo swanctl --list-algs
sudo swanctl --list-pols
```

Verify that the selected `emlkem...` algorithm appears and that the
`bypass-ssh` pass policy is installed before continuing.

## Reproduce Table 2 from fresh packet captures

Table 2 is an empirical result, not merely an assumed constant. On the
author-provided ECS initiator and responder, first complete the endpoint setup
in [Complete network rerun](#complete-network-rerun): install the certificates,
configure and install `strongswan.conf` and the appropriate `swanctl.conf`,
select the same proposal on both ends, and start `charon`. Load the configured
swanctl objects with `sudo swanctl --load-all` and verify that the selected
proposal is available before capturing. The capture script is not standalone;
it expects the configured IKEv2 endpoints and a running daemon.

After changing a proposal or either endpoint configuration, copy the updated
files into place, restart `charon` when `/etc/strongswan.conf` changes, and run
`sudo swanctl --load-all` again before starting a new capture. Then run on the
initiator:

```bash
sudo bash experiment/scripts/capture_ike_sa_init.sh \
  experiment/local/emlkem768.pcap any
bash experiment/scripts/inspect_ike_pcap.sh \
  experiment/local/emlkem768.pcap
```

The summary lists the two IKE_SA_INIT packets and `isakmp.length`. That value
is the paper's SA_INIT net size: it excludes the 40-byte IPv6 and 8-byte UDP
headers. For the Table 2 field breakdown, either run the verbose tshark command
printed by the script or open the pcap in Wireshark and expand **Internet Key
Exchange v2**. Account for the IKE header, SA, KE header, Nonce, Notify, and
Certificate Request fields. The expected breakdown is preserved in
`reference_results/ike_overhead_breakdown.csv`.

Repeat after selecting each implementation-supported proposal:

```text
aes128-sha256-ecp256
aes192-sha256-ecp384
aes256-sha256-ecp521
aes128-sha256-mlkem512
aes192-sha256-mlkem768
aes256-sha256-mlkem1024
aes128-sha256-emlkem512
aes192-sha256-emlkem768
aes256-sha256-emlkem1024
```

For every supported algorithm, subtract its public-key size from the
initiator IKE length and its ciphertext size from the responder IKE length.
The results should be 208 and 241 bytes respectively. Table 1 then applies
these validated fixed overheads to the other KEM sizes from their official
specifications; run `calculate_packet_sizes.py --check-paper-values` to check
that derivation.

## Recollect latency data for Table 4/Figure 6

### 1. Collect a route/algorithm run

On the initiator:

```bash
sudo bash experiment/scripts/run_latency.sh \
  experiment/local/route-a-emlkem768.log 1000 1 2
python3 experiment/scripts/parse_latency_log.py \
  experiment/local/route-a-emlkem768.log
```

The arguments are output log, iterations, post-initiation settling seconds,
and termination timeout. The parser reports successful samples, decryption
retries, and transport/handshake failures, and emits sorted latency JSON.

To convert every `.log` file directly under `experiment/local/` in one run,
pass the directory instead of a single file:

```bash
python3 experiment/scripts/parse_latency_log.py experiment/local
```

Each result is written beside its source with the same base name and a `.json`
extension (for example, `route-a-emlkem768.log` becomes
`route-a-emlkem768.json`). Existing JSON files with those names are replaced.
Files in nested directories are not included. To place all generated files in
another existing directory, add `--output DIR`; for a single log, `--output`
continues to accept a JSON filename. The parser streams each complete log from
beginning to end and does not impose a 1,000-sample limit.

For a close reproduction, run all four proposals on the same supplied route
pair before moving to the next pair. Use the private handoff for the route
mapping. Record `ping -6` RTT/TTL and keep host shapes, bandwidth limits, and
strongSwan configuration constant.

The four proposals used for the latency comparison are:

```text
aes192-sha256-ecp384
aes192-sha256-emlkem768
aes256-sha256-mlkem1024
aes256-sha256-emlkem1024
```

Both endpoints must use the same proposal. The supplied `ikev2-test`
connection intentionally has no `children` block: the capture and latency
scripts invoke `swanctl --initiate --ike ikev2-test` and
`swanctl --terminate --ike ikev2-test`, so they measure establishment and
teardown of the IKE_SA only. No CHILD_SA, ESP security association, or IPsec
data-plane policy is created for this connection. Consequently, no protected
subnet placeholders need to be filled in for `ikev2-test`.

Both supplied templates also install a `bypass-ssh` pass policy for inbound
IPv6 TCP port 22. Keep this block when changing proposals so SSH management
traffic is excluded from IPsec processing. This pass policy protects
connectivity from IPsec policy mistakes; it does not replace the ECS security
group or host firewall.

### 2. Interpret differences

Exact WAN results are not deterministic. Confirm these qualitative outcomes:

- eMLKEM-768 and ECDH remain unfragmented under the 1280-byte IPv6 MTU;
- ML-KEM-1024 exceeds a 1500-byte MTU and fragments;
- eMLKEM-1024 remains within that deployment MTU;
- fragmentation has the largest latency/reliability cost on lossy routes;
- a detected eMLKEM failure causes at most the configured bounded retry.

## Data provenance and privacy

The distributed JSON arrays were derived from the logs used for the
multi-region latency result. Raw historical logs and pcaps were omitted because
they contained endpoint addresses and added more than 250 MB. Evaluators can
create fresh pcaps and logs on the temporary ECS nodes. No timestamps,
endpoint identifiers, credentials, or packet payloads remain in the public
reference arrays. Access details remain exclusively in the confidential AE
handoff and are deleted or revoked when the temporary service is retired.
