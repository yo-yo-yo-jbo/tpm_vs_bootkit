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
PCRn = TPM_Extend(PCRn, buffer) = hash(PCRn, || hash(buffer))
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

UEFI uses TCG2 API as such:

```c
EFI_STATUS
HashLogExtendEvent(
  IN EFI_TCG2_PROTOCOL*    This,
  IN EFI_PHYSICAL_ADDRESS  DataToHash,
  IN UINT64                DataLength,
  IN EFI_TCG2_EVENT*       EfiTcgEvent
);
```

Note the API gets the buffer *as is* (`DataToHash` and `DataLength`) rather than getting a hash - it does the hashing itself.

### Sealing and unsealing
One incredible ability TPM has is the ability to perform *sealing* and *unsealing* of secrets and tie that to PCR values.  
Here is an example that shows how it's done:

```c
// Required headers
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <string.h>
#include <stdio.h>

void seal_data(ESYS_CONTEXT *esys_ctx)
{
    TSS2_RC rc;
    ESYS_TR session = ESYS_TR_NONE;
    ESYS_TR primary_handle = ESYS_TR_NONE;
    ESYS_TR sealed_obj_handle = ESYS_TR_NONE;
    TPM2B_PUBLIC *out_public = NULL;
    TPM2B_PRIVATE *out_private = NULL;

    // Start a policy session
    rc = Esys_StartAuthSession(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, NULL, TPM2_SE_POLICY, TPM2_ALG_SHA256, TPM2_ALG_SHA256, &session);

    // Build PCR selection (bind to PCR 7)
    TPML_PCR_SELECTION pcr_selection = {
        .count = 1,
        .pcrSelections = {
            {
                .hash = TPM2_ALG_SHA256,
                .sizeofSelect = 3,
                .pcrSelect = {0, 0, 0x80}  // PCR 7
            }
        }
    };

    // Call TPM2_PolicyPCR to bind the session to current PCR[7]
    rc = Esys_PolicyPCR(esys_ctx, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, &pcr_selection);

    // Get the resulting policy digest
    TPM2B_DIGEST *policy_digest = NULL;
    rc = Esys_PolicyGetDigest(esys_ctx, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &policy_digest);

    // Set up object templates
    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = {.size = 0},
            .data = {.size = 6, .buffer = "SECRET"}
        }
    };

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_KEYEDHASH,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                                TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_ADMINWITHPOLICY,
            .authPolicy = *policy_digest,
            .parameters.keyedHashDetail = {
                .scheme.scheme = TPM2_ALG_NULL,
            },
            .unique.keyedHash.size = 0,
        }
    };

    // Create primary key under the owner hierarchy
    rc = Esys_CreatePrimary(esys_ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
        ESYS_TR_NONE, &inSensitive, &inPublic, NULL, NULL, &primary_handle,
        NULL, NULL, NULL, NULL);

    // Create the sealed object under the primary key
    rc = Esys_Create(esys_ctx, primary_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &inSensitive, &inPublic, NULL, NULL, &out_private, &out_public, NULL, NULL, NULL);

    // Done with session
    Esys_FlushContext(esys_ctx, session);
}
```

Let's follow the concepts of this code:
1. We call `Esys_StartAuthSession` to create a session.
2. We define a `TPML_PCR_SELECTION` structure that defines the PCR values we are interested of binding the sealing with. In our case we chose PCR7, which corresponds to the value `0x80` (it's a bitmask). Of course, we could bind it to multiple PCR values.
3. We call `Esys_PolicyPCR` to declare that data structure (the PCR selection) and bind that to the session we created.
4. We generate a structure of type `TPM2B_SENSITIVE_CREATE` which will contain the secret buffer in it (the buffer we are going to seal).
5. We create a *primary key* with `Esys_CreatePrimary` for the particular secret. There is a hierarchy associated with public keys but we won't do a deep dive here.
6. We create a sealed object under that primary key using `Esys_Create`.

To unseal, we do the following:

```c
void unseal_data(ESYS_CONTEXT *esys_ctx, ESYS_TR parent_handle,
                 TPM2B_PRIVATE *in_private, TPM2B_PUBLIC *in_public) {
    TSS2_RC rc;
    ESYS_TR session = ESYS_TR_NONE;
    ESYS_TR sealed_handle = ESYS_TR_NONE;

    // Load the object under the primary key
    rc = Esys_Load(esys_ctx, parent_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        in_private, in_public, &sealed_handle);

    // Start a policy session
    rc = Esys_StartAuthSession(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
        ESYS_TR_NONE, NULL, NULL,
        TPM2_SE_POLICY, TPM2_ALG_SHA256, TPM2_ALG_SHA256, &session);

    // Re-bind to PCR 7 (must match the PCR state at sealing time)
    TPML_PCR_SELECTION pcr_selection = {
        .count = 1,
        .pcrSelections = {
            {
                .hash = TPM2_ALG_SHA256,
                .sizeofSelect = 3,
                .pcrSelect = {0, 0, 0x80}
            }
        }
    };

    rc = Esys_PolicyPCR(esys_ctx, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        NULL, &pcr_selection);

    // Now unseal the data
    TPM2B_SENSITIVE_DATA *out_data = NULL;
    rc = Esys_Unseal(esys_ctx, sealed_handle, session, ESYS_TR_NONE, ESYS_TR_NONE, &out_data);

    if (rc == TSS2_RC_SUCCESS) {
        printf("Unsealed data: %.*s\n", out_data->size, out_data->buffer);
    } else {
        printf("Unseal failed: 0x%x\n", rc);
    }

    // Cleanup
    Esys_FlushContext(esys_ctx, session);
    Esys_FlushContext(esys_ctx, sealed_handle);
}
```

1. Note we've done similar first steps - we have created a session, defined a PCR selection structure and perform a binding using `Esys_PolicyPCR`.
2. Now we call `Esys_Unseal` to unseal the data. The most important thing is this - *unsealing fails if the PCR selection and the values themselves mismatch*.

That is a very powerful thing - this means unsealing data now is tightly bound to the boot order, configuration, and generally - buffers controlled by the firmware.  
We'll see how Bitlocker uses that.
