# Artifact for "Dance with Noise"

This repository contains the camera-ready artifact for the paper **"Dance with
Noise: Safely Trade Minor Decryption Failures for More Compact KEMs with
Applications to IKEv2."** It supports Sections 4.3 and 5, including the
packet-size derivation (Table 1), measured IKE overhead (Table 2), standalone
KEM evaluation (Table 3), and multi-region latency evaluation(Table 4/Figure 6).

**Permanent artifact DOI:** `https://doi.org/10.5281/zenodo.22747226`

Replace this token with the long-term Zenodo (or equivalent archival) DOI in
every public document before publishing the camera-ready artifact.

- [`standalone_emlkem/`](standalone_emlkem/) contains the standalone ML-KEM
  and eMLKEM implementations and the Table 3 workflow.
- [`strongswan_6.0.4_inc/`](strongswan_6.0.4_inc/) contains only this
  artifact's changed strongSwan files, relative to upstream commit `6856bfe`,
  including the `mlex` plugin and bounded IKE_SA_INIT retry. The complete
  upstream tree is intentionally not distributed; see the preparation steps
  below.
- [`experiment/`](experiment/) contains safe configuration templates,
  tcpdump/Wireshark instructions for the measured Table 2 IKE overhead,
  Table 1 derivation, and multi-region latency workflows/data.

See [`ARTIFACT_APPENDIX.md`](ARTIFACT_APPENDIX.md) for the evaluator-oriented
workflow.

## Permanent archive and temporary AE service

The Zenodo archive is the permanent artifact. It contains source code,
configuration templates, scripts, and anonymized reference results. Anyone
using that archive after the conference must provide their own Linux hosts,
network connectivity, administrator access, strongSwan installation, and test
credentials.

During the conference AE period only, the authors additionally provide a set
of disposable, preconfigured ECS instances. Assigned evaluators receive
time-limited SSH access through the confidential AE portal and may use `sudo`
on those instances to switch proposals, reload strongSwan, capture packets,
and, if necessary, rebuild the software. The ECS instances, their credentials,
addresses, raw logs, and packet captures are not part of the permanent
artifact and are not promised to remain available after AE.

## Quick start (about 5 minutes)

On Ubuntu 22.04 or a comparable x86-64 Linux system:

```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev python3
make -C standalone_emlkem smoke
./standalone_emlkem/e768-smoke
python3 experiment/scripts/analyze_latency.py --check-paper-values
python3 experiment/scripts/calculate_packet_sizes.py --check-paper-values
```

The executable and both Python commands should finish with a line beginning
with `PASS:`.

To regenerate Figure 6:

```bash
python3 -m pip install matplotlib
python3 experiment/scripts/generate_plots.py
```

Plots are written to `experiment/generated/figure6/`.

## Prepare the modified strongSwan source

The incremental files are based on commit `6856bfe` from the official
[`strongswan/strongswan`](https://github.com/strongswan/strongswan.git)
repository. From the artifact root, fetch that exact revision and apply the
incremental files with:

```bash
bash experiment/scripts/prepare_strongswan.sh
```

This creates the untracked working directory `strongswan_6.0.4/`, checks out
the fixed upstream revision in detached-HEAD state, and copies every file from
`strongswan_6.0.4_inc/` over the same relative path. It refuses to overwrite a
non-Git directory or a checkout at another revision. Network access to GitHub
is required for the initial checkout. The build command in
`experiment/README.md` invokes this preparation and verification step
automatically.

## Reproduction levels

| Workflow | Paper result | Requirements | Typical time |
|---|---|---|---|
| Basic functionality | eMLKEM works | One Linux host | 5-10 min |
| Standalone benchmark | Table 3 | One Linux host; fixed CPU recommended | 10-20 min |
| Packet capture | Table 2, then Table 1 derivation | Supplied IPv6 ECS pair, root, tcpdump/Wireshark | 3-5 min per proposal |
| Reference-data replay | Table 1 and multi-region latency result | Python 3; matplotlib for plots | 1-5 min |
| Full network rerun | Global-node latency result | Author-supplied ECS nodes and private access handoff | Hours to days |

Cycle counts and wide-area latency are environment-dependent. Exact
key/ciphertext sizes and functional outcomes should reproduce; performance
values should show similar trends on different hardware or routes.

## Safety and privacy

The quick-start and reference-data workflows are unprivileged. The full
network workflow requires administrator access, writes strongSwan files below
`/etc`, starts/stops `charon`, and creates IPsec policies. Assigned evaluators
may perform these actions on the temporary ECS instances. Other users must use
machines they own or administer. In either case, use disposable or dedicated
test hosts and keep an independent management connection.

## Licensing

See [`LICENSE`](LICENSE),
[`standalone_emlkem/LICENSE`](standalone_emlkem/LICENSE), and the upstream
[`strongSwan licensing information`](https://github.com/strongswan/strongswan/blob/6856bfe/COPYING).
