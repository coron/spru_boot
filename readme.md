# SPRU: Sparse Roots of Unity Bootstrapping for CKKS

This repository provides an [OpenFHE](https://github.com/openfheorg/openfhe-development)-based implementation of **SPRU bootstrapping** (*Sparse Roots of Unity Bootstrapping*), a novel CKKS bootstrapping method optimized for ciphertexts with a small number of slots. The implementation follows the algorithm described in our accompanying paper.

[1] Jean-Sébastien Coron and Robin Köstler. *Low-Latency Bootstrapping for CKKS using Roots of Unity*. Cryptology ePrint Archive, Paper 2025/651, 2025. [https://eprint.iacr.org/2025/651](https://eprint.iacr.org/2025/651)

SPRU bootstrapping offers reduced multiplicative depth and lower latency compared to the original CKKS bootstrapping, in scenarios where only a small number of slots are used.

---

## Installing OpenFHE

Install [OpenFHE](https://openfhe.org) by following the
[official documentation](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html).

The only difference for this project is that you must apply the patch below before building OpenFHE.
The patch changes one member of `FHECKKSRNS` from `private` to `protected`, which allows running `Slots2Coeff` independently of OpenFHE's original CKKS bootstrapping flow.

1. Clone the OpenFHE repository (HTTPS):
```bash
git clone --branch v1.4.2 https://github.com/openfheorg/openfhe-development.git openfhe-dev
```

If you prefer SSH:

```bash
git clone --branch v1.4.2 git@github.com:openfheorg/openfhe-development.git openfhe-dev
```

2. Apply the required patch before building and installing OpenFHE:

```bash
cd openfhe-dev
cp /path/to/spru_boot/patches/openfhe-ckksrns-protected.patch .
git apply openfhe-ckksrns-protected.patch
```

3. Build and install the library:

```bash
mkdir build
cd build
cmake ..
sudo make install
```

Note: on macOS, if you get an error about a missing regular expression backend, run:

```bash
cmake -DCMAKE_CROSSCOMPILING=1 -DRUN_HAVE_STD_REGEX=0 -DRUN_HAVE_POSIX_REGEX=0 ..
cmake ..
```

## Building the SPRU bootstrapping code

1. Clone this repository and navigate to its root directory.
2. Build the project:

```bash
mkdir build
cd build
cmake ..
make
```

## Running the demos

You can run either the original CKKS bootstrapping or the new SPRU bootstrapping:

```bash
./test-ckks-bootstrapping     # Original CKKS bootstrapping
./test-new-bootstrapping      # SPRU bootstrapping (new method)
```

## Modifying the number of threads

To control OpenMP parallelism, set the number of threads before running the demos:

```bash
export OMP_NUM_THREADS=8
```

## License

This code is open source and provided under the terms of the [LICENSE](./LICENSE).

## Third-Party Notices

See [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md).