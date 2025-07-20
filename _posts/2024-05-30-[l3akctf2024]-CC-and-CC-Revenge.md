The "CC" and "CC Revenge" challenges in the L3akCTF 2024 CTF revolve around decrypting a given ciphertext to retrieve the flag. Both challenges involve an `encrypt` function that encrypts plaintext and provide the encrypted flag, which participants must decipher.
# CC
First, let's examine the encrypt function's input:
![](/media/Pasted%20image%2020240529152142.png)
- `local_18`: a buffer of size 24
- `0xbadc0ffee`: some value
- `0xdeadbeef00000000`: some value
- a long string, assuming this is the cipher text
- `0x2b`

To simplify our approach, we'll focus on dynamic analysis and debugging instead of delving into all the inputs.

The encryption process is handled by the `feistel_cipher` function. Here's its input:
```
$rdi = 0x0000000badc0ffee
$rsi = 0xdeadbeef00000000
$rdx = 0x7777772e796f7574 // b'www.yout'
$rcx = 0x68747470733a2f2f // b'https://'
$r8  = 0x0
```
The `encrypt` function splits the plaintext into 16-byte chunks. Each chunk is divided into two 8-byte halves and passed to `feistel_cipher`, with the ciphertext returned through the `rax` and `rdx` registers:
```
rax = 0x1068e1e5eef92b2c
rdx = 0x3595ba73bc5a6be
```
These values are written to `ciphertext.bin`:
```
nyly@nyly-mint:CC$ xxd ciphertext.bin
00000000: 1068 e1e5 eef9 2b2c 0359 5ba7 3bc5 a6be  .h....+,.Y[.;...
00000010: c5d8 3b1e cf84 d295 6e3f d231 d3f8 acb6  ..;.....n?.1....
00000020: 1b69 4c22 2e28 93e5 a7ec 700b 47fe 9e4e  .iL".(....p.G..N
```

Examining the binary we find that before `encrypt` returns, it calls `decrypt` function

![](/media/Pasted%20image%2020240529151238.png)

This function also calls `feistel_cipher`, but with the last argument set to `0x1` instead of `0x0`, indicating a decryption operation:

![](/media/Pasted%20image%2020240529170105.png)

so let's try to pass the output of the `rax` and `rbx` above to see if we can reverse the operation, first we set a breakpoint at `call feistel_cipher` and then we set the registers with the desired input
```
gef➤  set $rdx = 0x03595ba73bc5a6be
gef➤  set $rcx = 0x1068e1e5eef92b2c
gef➤  set $r8 = 0x1
gef➤  ni
gef➤  p $rax
$1 = 0x7777772e796f7574 // b'www.yout'
gef➤  p $rdx
$3 = 0x68747470733a2f2f // b'https://'
```

Now that we've decrypted the ciphertext, we can apply these steps to the `flag.bin` file. We'll split it into 8-byte chunks and pass each pair of chunks to `feistel_cipher`.

Here's a script to automate this process:
```py
import gdb

victor = []

offset = 0x55555555e930 - 0x0010a930

def set_break(addr):
    gdb.execute(f"b *{hex(offset + int(addr, 16))}")

with open("flag.bin", "rb") as f:
    data = f.read()
    for i in range(0, len(data), 8):
        victor.append(int(data[i:i+8].hex(), 16))


set_break('0010fe8a')

gdb.execute('run')

flag = b''
for i in range(0, len(victor), 2):
    gdb.execute("set $rcx = " + f"{hex(victor[i])}")
    gdb.execute("set $rdx = " + f"{hex(victor[i + 1])}")
    gdb.execute("ni")
    first = bytes.fromhex(gdb.execute("p $rax", to_string=True).split(' ')[-1].replace('\n', '')[2:])
    second = bytes.fromhex(gdb.execute("p $rdx", to_string=True).split(' ')[-1].replace('\n', '')[2:])
    flag += second + first
    gdb.execute("c")

print(flag)
```

flag: `L3AK{its_all_started_with_C}`
# the Revenge

The CC Revenge challenge is similar to CC but without a `decrypt` function. The `feistel_cipher` function now accepts only four arguments and can only perform encryption. The plaintext is passed via `argv[1]`:

![](/media/Pasted%20image%2020240530153153.png)

For comparison, here's the `feistel_cipher` function in CC:

![](/media/Pasted%20image%2020240530153455.png)

so lets try calling the two functions with the same input, we'll call CC revenge's `feistel_cipher` function with the input we passed to CC in the above section.
```
nyly@nyly-mint:CC_Revenge$ gdb --args CC_revenge blablablablabla
gef➤  b *0x555555564cc0
gef➤  run
...
gef➤  set $rdx = 0x7777772e796f7574
gef➤  set $rcx = 0x68747470733a2f2f
gef➤  ni
...
gef➤  p $rax
$1 = 0xe58387f7c9c8f504
gef➤  p $rdx
$2 = 0x1dd2a744bb7e588f
```
the output is different, the reason of this is that `f` function has been modified so that the solution for CC don't work here too. so what i did is run 2 gdb instances, one for CC and one for CC Revenge, the CC Revenge just read input from `/tmp/args`, breakpoint to `f` function and then pass that input and write the output to `/tmp/return`
```py
import gdb


offset = 0x55555555e930 - 0x0010a930

def set_break(addr):
    gdb.execute(f"b *{hex(offset + int(addr, 16))}")

def main():
	# set a break at `call f`
    set_break("00110921")
    gdb.execute(f"run")

	# read from /tmp/args and set rsi and rdx
    with open("/tmp/args", "r") as f:
        args = f.read().split(" ")
        gdb.execute(f"set $rsi = {args[0]}")
        gdb.execute(f"set $rdx = {args[1]}")
        gdb.execute(f"p $rsi\np $rdx")

	# capture the return and write it in /tmp/return
    gdb.execute(f"ni")
    rax = gdb.execute("p $rax", to_string=True).split(" ")[-1].replace('\n', '')
    print(rax)
    with open("/tmp/return", "w") as f:
        f.write(f"{rax}")
    #gdb.execute("disconnect")

if __name__ == "__main__":
    main()
```

the CC instance run intel `f` function, write the input passed to it to `/tmp/args`, wait for the first instance then read the output in `/tmp/return` and then override the return of `f`, its like we're calling CC's decrypt but we manipulate the execution to make it uses CC revenge's `f` instead of it's own.
```py
victor = []

def fil_victor():
    with open("flag.bin", "rb") as f:
        data = f.read()
        for i in range(0, len(data), 8):
            victor.append(int(data[i:i+8].hex(), 16))

def test():
    set_break("0010fe8a") # call feistel_cipher
    set_break("0010fe8f") # instruction after `call feistel_cipher`
    set_break("0010f6f0") # f

    gdb.execute("run")
    gdb.execute(f"set $rdx = {victor[1]}") // im lazy so you need to change this
    gdb.execute(f"set $rcx = {victor[0]}") // to victor[3] and victor[2] when the first part is decrypted :)
    gdb.execute("c")
    while True:
        with open("/tmp/args", "w") as f:
            rsi = gdb.execute("p $rsi", to_string=True).split(" ")[-1].replace('\n', '')
            rdx = gdb.execute("p $rdx", to_string=True).split(" ")[-1].replace('\n', '')
            f.write(f"{rsi} {rdx}")
        input("wait for other script cuz im lazy....")
        with open("/tmp/return", "r") as f:
            rax = f.read()
        gdb.execute(f"ni")
        gdb.execute(f"set $rax = {rax}")
        print(rax)
        gdb.execute("c")
    #apply_hash_output()


if __name__ == "__main__":
    fil_victor()
    test()
```

i then alt tabed to run the CC Revenge instance while the CC instance is waiting, then alt-tabed back to click enter to stop the waiting, repeat this approximately 30 times intel CC instance break in the instruction after `call feistel_cipher` and the deciphered output will be in `rax` and `rdx` (so sorry im too lazy to write a proper solution 😅)

flag: `L3AK{R3venge_0f_Th3_Sch1ffy}`
# conclusion
gdb scripting is cool
