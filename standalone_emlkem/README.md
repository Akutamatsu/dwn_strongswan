# Standalone ML-KEM/eMLKEM evaluation

This directory supports Section 4.3 and Table 3. It contains the reference
ML-KEM (IND-CCA) comparison and this paper's eMLKEM (IND-CPAF) implementation
for security levels 1, 3, and 5.

## Requirements

- x86-64 Linux (evaluated on Ubuntu 22.04)
- GCC 9 or newer and GNU Make
- OpenSSL development headers
- Python 3
- SageMath only when recomputing LWE estimates

Cycle measurements in the paper used an Intel Core i7-10700 at 2.90 GHz.
Different CPUs should reproduce sizes and functionality exactly but not exact
cycle counts.

## Basic test 

From the repository root:

```bash
make -C standalone_emlkem smoke
./standalone_emlkem/e768-smoke
```

Expected final output:

```text
PASS: eMLKEM-768 key generation, encapsulation, and decapsulation
```

The smoke test retries a detected decapsulation failure, which is expected
behavior for this construction, and rejects any undetected key mismatch.

## Reproduce the implementation rows of Table 3 (3-5 minutes)

The full tests use 100,000 iterations per scheme and parameter set:

```bash
cd standalone_emlkem
python3 run_tests.py --force
```

This compiles and runs the ML-KEM and eMLKEM failure/correctness programs and
cycle benchmarks. Raw outputs are saved beside their executables. Use `-v` to
stream output. Without `--force`, an existing result file is reused.

The observed number of eMLKEM failures is deterministic for the test program's
random stream but is a sample, not the theoretical failure probability. The
paper observed 7, 7, and 24 failures for eMLKEM-512/768/1024 in 100,000 runs.

## Security and failure estimates (4-6 minutes)

The customized parameter definitions are in `security-estimates/schemes.py`.
The lattice-estimator project (https://github.com/malb/lattice-estimator.git) explicitly does not guarantee API stability, we use the commit hash `53da5982597709ba0fdf94ea37a84d822310fd84`. 

```bash
cd security-estimates
git clone https://github.com/malb/lattice-estimator.git
cd lattice-estimator
git checkout 53da598
cd ../..
```
The setup script prints the checked-out commit after installation. The failure estimates script calls the script `Kyber_failure.py` modified from https://github.com/pq-crystals/security-estimates.git commit `75c2694`.

```bash
python3 security-estimates/setup_lattice_estimator.py
python3 security-estimates/run_lwe_estimates.py
python3 security-estimates/run_failure_estimates.py
```

The LWE step requires SageMath. The failure-probability step uses the included
Python estimator. Reference Table 3 values are preserved in
`reference_results/table3.csv`, allowing evaluation when SageMath is not
available.

## Generate Table 3

After the full tests and estimators have produced their `.txt` files:

```bash
python3 generate_table.py
```

This writes `benchmark_table.tex`. `Sec.(C)` is the rounded `usvp` cost
exponent. KGen, Encap, and Decap values are average cycles divided by 1000 and
rounded to the nearest integer.

## Source organization

- `src/kem_cpaf.c`: eMLKEM KEM construction
- `src/kem_cca.c`: ML-KEM comparison construction
- `failure_test/`: 100,000-iteration correctness/failure programs
- `speed_test/`: 100,000-iteration cycle benchmarks
- `security-estimates/`: concrete-security and DFR estimation
- `run_tests.py`: full benchmark driver
- `generate_table.py`: Table 3 generator

This code is a research prototype and is not intended for production use.
