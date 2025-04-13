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

| Index | PCR Purpose                             |
| ----- | --------------------------------------- |
| 0     | BIOS/UEFI firmware code                 |
| 1    	| BIOS configuration (setup)              |
| 2	    | Option ROMs (e.g., GPU or NIC firmware) |
| 3	    | MBR or GPT (bootloader components)      |
| 4	    | Bootloader (e.g., GRUB, Bootmgr)        |
| 5	    | Boot manager configuration              |
| 6	    | OS loader code                          |
| 7	    | Secure Boot policy                      |
| 8–15	| OS-specific drivers and applications    |
