# Flush and Reload, a LLC Cache Side Channel Attack

This repository is an implementation of a flush-reload side channel attack.

<!-- This attack should be performed on a virtual machine dedicated for the execution of this program. So the safety of your
host machine will not be affected in any way. -->

It mounts an attack on OpenSSL's AES-128's T-table implementation. In order to perform this attack on your own machine, follow the steps outlined below.

## OpenSSL Installation

Trusted versions of OpenSSL can be found at: https://www.openssl.org/source/old/. This attack may not work for most versions, but the specific version we use is version `openssl-1.1.0f`. Download the tarball and extract it with the following commands:

```bash
wget https://github.com/openssl/openssl/releases/download/OpenSSL_1_1_0f/openssl-1.1.0f.tar.gz
tar -xvf openssl-1.1.0f.tar.gz
```

Now we need to configure OpenSSL to use its T-table C implementation as opposed to the Assembly implementation default. OpenSSL also needs to be configured with debug symbols and specified to use a shared object (`.so`) as opposed to an `.a` library.

For the appropriate configuration, run the following commands in the root directory of this repository:

```bash
cd openssl-1.1.0f
./config -d shared no-asm no-hw
```

> **NOTE**: It may happen that the configuration fails depending on the machine. If this happens, run the following command in the OpenSSL folder:<br>
> `grep -nr "qw/glob/"`<br>
> And in all the above files, replace it with the code: `qw/:glob`. Then run the configuration command again.
<br>

For the selected version: `1.1.0f`, this configuration will install OpenSSL in the `/usr/local/lib` directory. The configuration parameters specify that we allow for debug symbols (used to locate T-table locations), create a shared object, only use C implementations of AES (to use the T-tables), and to not use any hardware routines. To proceed with the install, run:

```bash
sudo make
sudo make install_sw
```

## Finding Cache Hit/Miss Threshold

This repo contains a calibration tool to automatically find the threshold for LLC cache miss / cache hit, curteousy of https://github.com/IAIK/flush_flush. Simply compile and run the tool with the following commands in the root directory of this repository:

```bash
gcc calibration.c -o calibration
./calibration
```

This should output an appropriate threshold for your machine. Edit the **`attacker.cpp`** file's **`MIN_CACHE_MISS_CYCLES`** constant with the suggested threshold.

## Finding T-table Addresses

A flush-reload attack monitors cache lines. To monitor the correct cache lines, we must find the offset of addresses of the T-tables with respect to the **libcrypto.so** shared object. To find this, perform the following commands in the root directory of this repository:

```bash
readelf -a /usr/local/lib/libcrypto.so > aeslib.txt
```

This will deconstruct the **libcrypto.so** file and allow us to find the appropriate address offsets. Run `grep` to find the offsets quickly. You will see an output similar to the following:

```bash
grep "Te0" aeslib.txt | awk '{print $2}'

# Output
00000000001df000
```
In this case, the offset is `0x1df000`. You can find the offsets for the other T-tables by searching for `Te1`, `Te2`, and `Te3`.

Take note of these offsets, and change the **`probe`** character array in **`attacker.cpp`** to the appropriate offsets for your specific machine.

## Compile and run the program

Since we have installed OpenSSL in a local directory instead of a system directory, we need to tell the linker to use the
appropriate version of OpenSSL. To do this, type in terminal at the root directory of this repository:

```bash
export LD_LIBRARY_PATH=/usr/local/lib
```

Now we can compile the program with below command. It will create two executables, `victim` and `attacker`.

```bash
make all
```

Run the victim and attacker programs in a separate terminal. Both programs should be run with the `taskset` command to ensure that they run on separate cores, so that the attack can be performed cross-core. Make sure to run the `victim` program first before running the `attacker` program.

```bash
taskset -c 0 ./victim
taskset -c 1 ./attacker <num_encryptions>
```

The `num_encryptions` parameter specifies the number of encryptions the attacker will perform. The attacker will then use the cache side channel to determine the key used in the victim's encryption.

For example, `taskset -c 1 ./attacker 5000` will run the `attacker` program with 5000 encryptions. It is recommended to run the `attacker` program with a large number of encryptions to ensure that the attack is successful. The `attacker` program will output the key used in the victim's encryption with a high degree of accuracy.

## References

- Yuval Yarom and Katrina Falkner. 2014. FLUSH+RELOAD: a high resolution, low noise, L3 cache side-channel attack. In Proceedings of the 23rd USENIX conference on Security Symposium (SEC'14). USENIX Association, USA, 719–732.
