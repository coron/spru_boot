# SPRU: Sparse Roots of Unity Bootstrapping for CKKS

This repository provides an [OpenFHE](https://github.com/openfheorg/openfhe-development)-based implementation of **SPRU bootstrapping** — *Sparse Roots of Unity Bootstrapping* — a novel CKKS bootstrapping method optimized for ciphertexts with a small number of slots. This implementation is based on the algorithm described in our accompanying paper.

[1] Jean-Sébastien Coron and Robin Köstler. *Low-Latency Bootstrapping for CKKS using Roots of Unity*. Cryptology ePrint Archive, Paper 2025/651, 2025. [https://eprint.iacr.org/2025/651](https://eprint.iacr.org/2025/651)

SPRU bootstrapping offers reduced multiplicative depth and lower latency compared to the original CKKS bootstrapping, particularly in scenarios where only a small number of slots are used.

---

## Prerequisites

Install [OpenFHE](https://openfhe.org) by following their 
[official documentation](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html).

### Clone OpenFHE

```bash
git clone git@github.com:openfheorg/openfhe-development.git openfhe-dev
```

### Build and install OpenFHE

```bash
mkdir build
cd build
cmake ..
make
sudo make install
```

**Note for macOS users:**
if you encounter an error about a missing regular expression backend, run:

```bash
cmake -DCMAKE_CROSSCOMPILING=1 -DRUN_HAVE_STD_REGEX=0 -DRUN_HAVE_POSIX_REGEX=0 ..
cmake ..
```

---

## Building the SPRU bootstrapping code

1. Clone this repository and navigate to its root directory.
2. Build the project:

```bash
mkdir build
cd build
cmake ..
make
```

---

## Running the demos

You can run either the original CKKS bootstrapping or the new SPRU bootstrapping:

```bash
./test-ckks-bootstrapping     # Original CKKS bootstrapping
./test-new-bootstrapping      # SPRU bootstrapping (new method)
```

---

## License

This code is open source and provided under the terms of the [LICENSE](./LICENSE).

