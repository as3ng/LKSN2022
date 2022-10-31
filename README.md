# LKSN2022

<img src="images/logo30.png">

<tr>

This is a mini repository of all CTF Jeopardy challenges from Day 2 and Day 3 of LKSN 2022. All the participants are high-schoolers and vocational high-schoolers.

The categories of the challenges are:
* Offensive VM (BlackBox-Style Boot2Root)
* Infrastructure Hardening (Same VM)
* Binary Exploitation
* Reverse Engineering
* Web Exploitation
* Forensics (Memory + Android Images)
* Cryptography

Most of the problem setters are currently Stanley Halim (Enryu#7942), Chrisando Pardomuan (siahaan#9550), and me. One VM is created by the judges.
Most of the challenges can be downloaded from the challenges folder and all the solvers are coming soon.

# Some of TL;DR Notes on Solving the Challenge

## Cryptography

### Asimetris
* Recover `p` and `q` from simple equation of `p+q` and `p-q` by either adding or substracting both values to get the `p` or `q`, then divide it by two
* Substitute one of the value to the preferred equation and recover the other value (etiher `p` or `q`)
* Proceed to do simple RSA decryption

```python
from Crypto.Util.number import *

#p + q
add = 223379143686991605913757974086904956084745586781597190619692710985715650928911483513137509353123147597339665299059424072622476694246904156546927298408118269271123361806343238722602036442655115818340034688896232223189973295741658184001817204589243258978967212714184766370816815910237779187926328093977218881808

#p - q
sub = 8041188401302580231953232611470031705073372820076201961972980796044157146478209529522752670787863054017473957201598215740991630617215055640514254433826877554617215635857445835948266118499779235308281783120188321470356533581561152123025082918028073334752568205606113149574997211657553613234856299620174308066
c = 10300835035449517657293596853464312614316283989546934826954268189206177754618159391493847628846386983594848973069333222681289574265506479282594430832281272626025503015619922945095110975459270730895415932764100259581369195606835752929525904329946439591174871297686126596470454219680065756528222657418502021813782109875446270491960835278563354484559753896586269193126227786098131973668060123305060570045988964442710962288533797999964923158348729711945491538777073724367351632467294727199953799815141141954884309061637335804185473426855488521046963093636687150594055437166201408552467239350431374970659499102590050673445
e = 65537
p = int(add + sub) // 2
q = add - p 
phi = (p - 1) * (q -1)
N = p * q
d = inverse(e, phi)

print(long_to_bytes(pow(c,d,N)))
```

### Varian 2048
* Since this is a simulation of how the RSA-encrypted message are sent to other "clients" with the **same** public exponent (`e`) and different modulus (`N`), we can conclude that this can be done using `Hastad Broadcast Attack`
* n(th)-times encryption means the value of exponent from `e` shall be the same as n(th) times, this means e ** 3.

```python
from Crypto.Util.number import *
import gmpy2
from output import *

#hastad broadcast attack

mul_N = N1 * N2 * N3 * N4 * N5 * N6
RECOV_N1 = mul_N // N1
RECOV_N2 = mul_N // N2
RECOV_N3 = mul_N // N3
RECOV_N4 = mul_N // N4
RECOV_N5 = mul_N // N5
RECOV_N6 = mul_N // N6

D1 = inverse(RECOV_N1,N1)
D2 = inverse(RECOV_N2,N2)
D3 = inverse(RECOV_N3,N3)
D4 = inverse(RECOV_N4,N4)
D5 = inverse(RECOV_N5,N5)
D6 = inverse(RECOV_N6,N6)

ENC_MESSAGE = (C1*D1*RECOV_N1 + C2*D2*RECOV_N2 + C3*D3*RECOV_N3 + C4*D4*RECOV_N4 + C5*D5*RECOV_N5 + C6*D6*RECOV_N6) % mul_N

flag = gmpy2.iroot(ENC_MESSAGE, 27)[0]
print(long_to_bytes(flag))
```

## Reverse Engineering

### Bahasa Ular

* Decompile the `.pyc` file
* Learn how the algorithm workflows
* Recover the `.malware` file by using a reverse-algorithm

```python
import this

solper = open("flag.txt.malware","rb").read()

placeholder_1 = ""
for content in range(len(solper)):
	placeholder_1 += chr(solper[content] ^ ord(this.s[content % len(solper)]))

for i in placeholder_1:
	print(chr(ord(i) ^ 2 ^ 3 ^ 7 ^ 9 ^ 11 ^13),end="")
```

### Tidak Ada

* Defeating simple Anti-Disassembly techniques by patching **one** byte of the challenge
* Recover the hardcoded encrypted flag with XOR calculation

Snipped-ource:
```c
void jump(){
	asm volatile(
  "xor %%rax, %%rax\n"
  "jz baba + 1\n"
  "baba:\n"
  ".byte 0xe8\n"
  : :
  : "%rax");
	validate();
}
```

### Password Aman

* UPX Packer, unpack it with the same tools -> `upx`
* Validate the flag by bruteforcing the input based on CRC32 Hash

```python
from zlib import crc32
import string
parsed = [0xad68e236,
          0x330c7795,
          0x2060efc3,
          0x4366831a,
          0x15d54739,
          0x916b06e7,
          0xf3b61b38,
          0x1b0ecf0b,
          0x916b06e7,
          0x29d6a3e8,
          0x3dd7ffa7,
          0x5767df55,
          0x3dd7ffa7,
          0x6dd28e9b,
          0x1ad5be0d,
          0xfcb6e20c
 ]

flag =""
c = 0
while c < len(parsed):
	if (c == len(parsed)):
		break
	for i in string.printable:
		if(crc32(i.encode()) == parsed[c]):
			print("Found! "+i)
			flag += i
			c += 1
print(flag)
```
