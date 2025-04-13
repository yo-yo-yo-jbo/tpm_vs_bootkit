# TPM vs. Bootkit
Last time [I explained](https://github.com/yo-yo-yo-jbo/bootkit_anatomy/) how Bootkits work.  
This time I want to convince you that all is not lost, and talk about what TPM does to help the situation, including how Bitlocker uses it.

## TPM at a highlevel
The [Trusted Platform Module (TPM)](https://en.wikipedia.org/wiki/Trusted_Platform_Module) is a dedicated hardware component designed to provide cryptographic functions and platform integrity assurances.  
Integrated into most modern systems, it plays a central role in securing operations such as disk encryption, secure boot, and attestation.  
At its core, the TPM can generate and protect cryptographic keys, securely store secrets, and maintain integrity measurements of the system's boot process using Platform Configuration Registers (PCRs).  
These capabilities make the TPM a foundational element in modern operating system security features, including BitLocker, which relies on the TPM to protect encryption keys and ensure the system has not been tampered with prior to boot.

### PCRs
One of the most important aspect of the TPM is the concept of Platform Configuration Registers (PCRs).  
Those are registers that hold the digest of a hash function (e.g. SHA1 or SHA256), thus quite long compared to normal CPU registers.  
PCRs are addressed by their number, such as "PCR 0", "PCR1" and so on. Here are common PCR numbers and how they're used:

| Number(s) | PCR Purpose                             |
| --------- | --------------------------------------- |
| 0         | BIOS/UEFI firmware code                 |
| 1        	| BIOS configuration (setup)              |
| 2	        | Option ROMs (e.g., GPU or NIC firmware) |
| 3	        | MBR or GPT (bootloader components)      |
| 4    	    | Bootloader (e.g., GRUB, Bootmgr)        |
| 5	        | Boot manager configuration              |
| 6	        | OS loader code                          |
| 7	        | Secure Boot policy                      |
| 8–15	    | OS-specific drivers and applications    |

Those PCR values initially get the value of 0, and then *extended* with TPM functionality - imagine the TPM exposes an API that looks like this:

```
PCRn = TPM_Extend(PCRn, hash(buffer))
```

This lets one create a *rolling hash* similar to how blockchain hashes look like. Since hash functions are (supposedly) one-way, supplying even one "wrong" bit to a buffer completely changes the future PCR values.  
The buffers supplied to the `TPM_Extend` function we have just introduced depend on the PCR index. Thus:
- Since `PCR0` contains firmware code rolling hashes, UEFI code is extended there (e.g. `PEI`, `DXE` and so on) as buffers.
- Since `PCR1` contains configuration, we extend hashes of user-defined firmware settings (Secure Boot, boot order, etc).
- Bootloader code is extended into `PCR4`.
- Boot configuration (e.g. GRUB2 commandline or BCD in Windows) are extended into `PCR5`.
- The OS loader code (`winload.efi` for Windows or the Linux kernel for Linux) gets extended into `PCR6`. This might also include drivers loaded at boot time.
- Measurements for Secure Boot (e.g. `KEK`, `DB` and `DBX`) are extneded into `PCR7`.
- Lastly, `PCR8 - PCR15` might be used freely by the OS. On Windows, drivers and boot-time services are extended into those, by the Windows Boot manager.

