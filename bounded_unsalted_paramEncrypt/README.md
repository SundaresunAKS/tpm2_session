# tpm2_session
this repo contain tpm2 session sample codes.

# Build Steps

*before follow the steps make sure to install the [tpm2-tss](https://github.com/tpm2-software/tpm2-tss) and [tpm2-tools](https://github.com/tpm2-software/tpm2-tools)*

## Step 1 (Run the tpm2-tools cmds)
*Clear the TPM*\
**sudo tpm2_clear**

*flush the transiant objects*\
**sudo tpm2_flushcontext -lts**

*change the owner hierarchy password*\
**sudo tpm2_changeauth -c o passBindAuth**

*define nv index of 0x01500020*\
**sudo tpm2_nvdefine 0x01500020 -s 32 -p "passNvAuth" -P "passBindAuth"**

## Step 2 (build and run the Bounded/Unsalted param encryption sample code)
*compile the code*\
**sh build.sh**

*run the code*\
**sudo ./app**

## Step 3 (Read NV data using tpm2-tools cmd)
**sudo tpm2_nvread 0x01500020 -P "passNvAuth" -o nvDataRead.txt**
**sudo cat nvDataRead.txt**

*makesure nvDataRead.txt contails "bound/unsalt with param encrypt"*

*This code was test in raspberry pi with slb7672*
*This code was modified form the [intergity test code of tpm2-tss](https://github.com/tpm2-software/tpm2-tss/tree/master/test/integration)*
