# Artifact Appendix

## A.1 Abstract

This camera-ready artifact contains the standalone eMLKEM implementation,
incremental files relative to strongSwan commit `6856bfe` used to integrate
eMLKEM into IKEv2, scripts
for correctness and performance experiments, and anonymized per-handshake
latency measurements. It supports the packet measurements and overhead
breakdown in Tables 1-2, Table 3, and the multi-region latency result reported
as Table 4/Figure 6. Licensing is described in the root `LICENSE` and component license files.

## A.2 Description & Requirements

`standalone_emlkem/` supports Section 4.3 and Table 3.
`strongswan_6.0.4_inc/` contains the files changed relative to upstream
strongSwan commit `6856bfe`; the complete upstream source tree is fetched only
when preparing a build.

`experiment/` contains configuration templates, tcpdump/Wireshark capture
instructions for Table 2, the resulting Table 1 derivation, new-run scripts,
and reference latency data. Start with the root `README.md`; use the component
READMEs for full commands.

### A.2.1 Security, privacy, and ethical concerns

Standalone tests and reference-data replay are unprivileged. The full network
experiment requires root access, writes configuration and locally generated
test credentials below `/etc/swanctl`, starts/stops the strongSwan `charon`
daemon, and creates IPsec policies. A bad configuration can disrupt networking
or an SSH session. Assigned evaluators may use `sudo` on the disposable ECS
instances supplied for the AE period. Users of the permanent archive must
provide machines they own or administer. In either case, keep a separate
management channel and inspect templates before deployment.

The implementation is a research prototype and must not protect production
traffic. eMLKEM intentionally has a non-negligible decryption failure rate.
No credentials, private keys, or original endpoint addresses are distributed
in the public archive. Time-limited ECS access details are supplied only to
the assigned evaluators through the confidential AE portal.

### A.2.2 How to access

The permanent, publicly archived camera-ready artifact is available at:

**DOI:** `https://doi.org/10.5281/zenodo.22747226`

Before publication, replace this token with the long-term Zenodo (or
equivalent) DOI. A maintained repository may also be listed here, but the DOI
archive is the immutable version evaluated for the badge.

The author-provided ECS instances are a separate, temporary AE convenience.
Their addresses and credentials are delivered only through the confidential
AE portal, expire after the evaluation window, and are not part of the DOI
archive. After that window, reproducing the full network experiment requires
self-provisioned hosts and administrator access.

### A.2.3 Hardware dependencies

The basic test and reference-data replay have no special hardware dependency.
Table 3 cycle counts were measured on an Intel Core i7-10700 at 2.90 GHz.
The complete network experiment used Ubuntu 22.04 ECS VMs with 2 vCPUs, 8 GiB
RAM, 20 Mbps public IPv6, and four inter-regional routes. The authors provide
evaluators with time-limited access to preconfigured nodes, so evaluators are
not expected to procure or deploy a global fleet. Other hardware and routes
reproduce functionality and trends, not exact timing.

### A.2.4 Software dependencies

- Ubuntu 22.04 or comparable x86-64 Linux
- GCC, GNU Make, Python 3, and OpenSSL development headers
- autoconf, automake, libtool, gperf, bison, flex, pkg-config, libgmp-dev,
  libsystemd-dev, and libcurl4-openssl-dev for strongSwan
- matplotlib for Figure 6
- the GitHub repository `https://github.com/strongswan/strongswan.git` at
  commit `6856bfe` for the modified strongSwan source tree
- the GitHub repository `https://github.com/malb/lattice-estimator.git` at
  commit `53da598` for fresh security estimates
- SageMath for fresh security estimates (saved reference values may be used
  otherwise)
- tcpdump for collection and Wireshark/tshark for inspecting new captures

### A.2.5 Benchmarks

No external dataset is required. Numeric per-handshake durations are in
`experiment/reference_results/latency/`; route properties and failure counts
are in `network_summary.csv`. Packet-size inputs are in `packet_sizes.csv`;
the measured Table 2 field breakdown is in `ike_overhead_breakdown.csv`.

## A.3 Set Up

Use an x86-64 Ubuntu 22.04 host for the closest match. Extract the artifact and
start at its root.

### A.3.1 Installation

```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev python3 python3-pip \
  libgmp-dev libsystemd-dev libcurl4-openssl-dev pkg-config bison flex \
  autoconf automake libtool gperf iproute2 iputils-ping tcpdump tshark
```

Install matplotlib with `python3 -m pip install matplotlib` when regenerating
plots. Full strongSwan instructions are in `experiment/README.md`.

Prepare the modified strongSwan working tree from the official upstream
repository (network access required):

```bash
bash experiment/scripts/prepare_strongswan.sh
```

The script checks out commit `6856bfe` as `strongswan_6.0.4/` and overlays
the files from `strongswan_6.0.4_inc/` using their original relative paths.

### A.3.2 Basic test

```bash
make -C standalone_emlkem smoke
./standalone_emlkem/e768-smoke
python3 experiment/scripts/analyze_latency.py --check-paper-values
python3 experiment/scripts/calculate_packet_sizes.py --check-paper-values
```

Each command must end with a line beginning with `PASS:`.

## A.4 Evaluation Workflow

### A.4.1 Major claims

**(C1)** eMLKEM has the public-key/ciphertext sizes, measured failure behavior,
classical security estimates, and operation costs (E1, Table 3).

**(C2)** Packet captures show a fixed IKE_SA_INIT overhead of 208 bytes from
initiator to responder and 241 bytes in the reverse direction (E2a, Table 2).
Applying those measured overheads shows that eMLKEM-768 fits below the
1280-byte IPv6 MTU and eMLKEM-1024 fits the 1500-byte deployment MTU, while
corresponding standard ML-KEM payloads require fragmentation (E2b, Table 1).

**(C3)** Unfragmented eMLKEM has latency close to classical ECDH and is more
robust than fragmented ML-KEM-1024 on adverse routes (E3, Table 4/Figure 6).

### A.4.2 Experiments

**(E1) Standalone eMLKEM evaluation**  
*10 person-minutes + 10-20 compute-minutes + less than 1 GiB disk.*

Preparation: Install build dependencies. Clone the lattice-estimator(53da598) from git repo as in `standalone_emlkem/README.md`.

Execution: Run `python3 standalone_emlkem/run_tests.py --force`, the two
security-estimate programs, then
`python3 standalone_emlkem/generate_table.py`.

Results: Compare the generated table to Table 3. Sizes and deterministic
failure counts should match. Cycle counts should preserve ordering and general
magnitude but vary by CPU and system load.

**(E2a) Capture and inspect IKE_SA_INIT packets**  
*3-5 person-minutes per proposal + less than 5 compute-minutes.*

Preparation: During AE, obtain the temporary ECS access information from the
confidential portal and use the supplied sudo access. Outside that period,
prepare two administrator-controlled IPv6 hosts using the supplied templates.
Select a supported proposal on both endpoints and reload strongSwan. Install
tcpdump on the initiator; use Wireshark or tshark for inspection.

Execution: Run `capture_ike_sa_init.sh` for a single handshake, then run
`inspect_ike_pcap.sh`. Repeat for the supported ECDH, ML-KEM, and eMLKEM
proposals listed in `experiment/README.md`. Inspect the two IKE_SA_INIT packets
and their common and Notify payload fields.

Results: The IKE message length excludes the 48-byte IPv6+UDP headers.
Subtracting the KE public-key/ciphertext data yields fixed overheads of 208
bytes for initiator-to-responder and 241 bytes for responder-to-initiator,
matching Table 2 and `ike_overhead_breakdown.csv`.

**(E2b) Derive the cross-scheme packet-size table**  
*2 person-minutes + less than 1 compute-minute.*

Preparation: Python 3 only.

Execution: Apply the E2a overheads to each published KEM size by running
`python3 experiment/scripts/calculate_packet_sizes.py --check-paper-values`.

Results: The command prints packet sizes/MTU margins and ends in `PASS`.

**(E3) Network latency and robustness**  
*Reference replay: 5 person-minutes + less than 1 compute-minute. Full rerun:
about 2 person-hours + 6-24 wall-clock hours.*

Preparation: For replay, install Python 3 and matplotlib. For a full rerun,
retrieve the confidential handoff for the temporary author-provided
multi-region ECS nodes from the AE portal and follow `experiment/README.md`.
Evaluators have sudo access and may rebuild/redeploy on those disposable nodes.
After AE, users must provide equivalent hosts themselves.

Execution: For replay, run `analyze_latency.py` and `generate_plots.py`. For a
full rerun, use `run_latency.sh` for each algorithm/route pair and convert each
log with `parse_latency_log.py`.

Results: Replay reconstructs the Table 4/Figure 6 latency statistics and
associated plots. Full-rerun absolute latency,
packet loss, and failure counts depend on current routes; compare qualitative
behavior rather than demanding identical values.

## A.5 Notes on Reusability

The standalone KEM supports all three parameter levels. The strongSwan plugin
registers `emlkem512`, `emlkem768`, and `emlkem1024`. New measurements can be
added to the manifest without changing the analyzer. The retry limit is
configured by `charon.max_ike_init_retries`; zero disables the added retry.
