======================
IMA and EVM Concepts
======================


The Linux Integrity Measurement Architecture (IMA) actions are
triggered based on :ref:`ima-policy-top` rules. IMA calculates hash values
of executables and other system files at runtime. The hash value is
used in multiple ways:

* stored in a IMA-Measurement event log
* used for verifying file signatures and hashes
* stored in the system audit log

The hash algorithm is defined by :ref:`config-ima-default-hash`, which
can be overridden by the :ref:`boot-command-line-arguments`
:ref:`ima-hash`.

* :ref:`ima-measurement` maintains an aggregate integrity value over
  the measurement event log if the platform has a TPM chip. The TPM can
  attest to the state of these system files. It typically uses PCR 10.
  The TPM attestation quote is a signature over the PCR, indirectly
  providing integrity over the measurement event log.

  The measurement feature requires both a TPM and an independent verifier.

  Measurement is similar to the pre-OS trusted boot concept. The first
  measurement is the boot aggregate, which is a hash of TPM PCR 0-9.

  IMA keeps a table of the measured hash values. If the hash is seen
  again, the contents are not re-measured
  again. :ref:`config-ima-disable-htable` offers other options.

* :ref:`ima-appraisal` can check the file's digital signature or
  hash and take action if the signature verification fails or the hash
  does not match a known good value.

  Appraisal is similar to the pre-OS secure boot concept.

  The :ref:`ima-appraisal` feature is local, and requires neither a
  TPM nor a separate verifier.

* :ref:`ima-audit` includes the file hash in the system's audit
  log. This can be useful for analytics and forensics.


Threat Model
===================================

.. warning::

   Under construction.

IMA detects an attempt to access an invalid file. The TPM provides
cryptographic integrity over the measurement log, which can be reported
to a verifier. It covers threats such as:

* Unsigned software.
* Software signed with an unknown or revoked key.
* Software that has been altered after signing.


The measurement log verifier can further detect:

* Running unapproved software.
* Running approved but back level software.
* A file with an unexpected file name.

These attacks are not in scope:

Memory Attacks
-----------------------------------

IMA measures and appraises files and other items when they are first
accessed.  An attack that modifies memory after the access will not be
detected.

Examples:

* A run-time alteration of memory, such as an mmap'ed file.
* An alteration of the appraise flag to disable appraisal.

File Name Changes
-----------------------------------

IMA does not appraise the file name, which is associated with the
directory, not the file meta-data.

For example, an the executable renamed from ``mv`` renamed to ``rm``
will still pass appraisal. The file name will be measured.

|


.. _ima-measurement:

IMA-Measurement
===================================


IMA-measurement has several steps:

#. Match attributes against a policy measurement rule.

#. If the rule applies, calculate a hash over the contents.

#. If the hash indicates a new measurement, append the measurement to
   the :ref:`ima-event-log` and extend the hash to a TPM PCR.

An attestation can then verify the integrity of the measurement log.
A TPM attestation quote is a signature over the PCR, in effect a
signature over the event log.

See :ref:`measure-policy-rule-design` for implications.

|

.. _ima-appraisal:

IMA-Appraisal
===================================

IMA Appraisal occurs only for file data. IMA generates a hash over the
file, and validates it against meta-data to determine whether the file
has been tampered with. File contents (not meta-data) appraisal comes
in two forms:

* :ref:`hash`
* :ref:`signature`

The :ref:`signature` attribute is required if the :ref:`policy-syntax`
rule condition :ref:`appraise-type` is present.  Its absence permits
the :ref:`hash` attribute in ``security.ima``.

See :ref:`extended-verification-module` for file meta-data appraisal.

See :ref:`appraise-policy-rule-design` for implications.

Appraisal requires files to be labeled with a security extended
attribute, stored in ``security.ima``. It can be viewed with

::

   getfattr -m - -e hex -d <file>

where ``-m -`` requests all attributes and ``-d`` dumps the values.

.. warning::

   https://github.com/mgerstner/ima-inspect does further parsing of the
   extended attributes.

   **FIXME Needs testing and a sample command line input and output.**

Signatures have a variation, called an ``appended signature``, where
the signature is appended to the file contents rather than stored in
the extended attribute.

Appraisal failures will return ``Permission denied``.  Further
information can be viewed in the system audit log with

::

   dmesg | tail


.. _hash:

Hash
-----------------------------------

.. warning::

   **FIXME Must test all the open read write rules**

This stores a file data hash in the extended attribute
``security.ima``.  The format is:

* 0x04 - ``IMA_XATTR_DIGEST_NG``
* hash algorithm see :ref:`signature-hash-algorithm`
* hash binary

See the :ref:`ima-appraise` boot command line argument and the
:ref:`appraise-type` policy rule condition.

When a policy rule is triggered:

* When in ``fix`` mode, hashes are updated if incorrect or does not
  exist.

* When in ``enforce`` mode, the hash is checked on a read and updated
  on a write, for both new and existing files.

  In detail, the hash is not updated on each write, which would affect
  performance.  It is updated on the last close for write.

Use case:

A typical provisioning starts by booting with the
:ref:`boot-command-line-arguments` :ref:`ima-appraise` in ``fix``
mode. Set a custom policy to read/write. Reading all appraised files
creates or updates the file hash in the ``security.ima`` extended
attribute.

On subsequent boots, configure ``enforce`` mode and a read policy.
This causes the system to validate the hash against the stored value
before using a file. If the hash does not validate, then access will
be denied.

If the use case permits system configuration files to be altered, use
a read/write policy. The hash will be updated on a write, even in
``enforce`` mode, permitting a subsequent read.

.. _signature:

Signature
-----------------------------------

Signed files are immutable and provide provenance.

Appraisal starts with digitally signing files.  Ideally, this will be
a distro signature.  The signature is stored in the extended attribute
``security.ima``. The private key is used to sign files, while the
public key on the :ref:`dot-ima` keyring is used to verify
signatures. The private key should not be available on the system,
which provides additional protection against tampering.

When IMA verifies signatures it will use the
:ref:`public-key-identifier`, which is part of the IMA signature in
``security.ima``, to find the verification public key.  The format of
the signature is described in the event log :ref:`sig` field, and
includes the :ref:`public-key-identifier`, :ref:`hash-algorithm` and
:ref:`signature-length`.  The :ref:`evmctl` utility can be used to
sign files.

Use appraisal in :ref:`ima-appraise` ``enforce`` mode. ``fix`` mode
cannot be used to re-sign a file because the private key should be
held elsewhere.

A user with a private key can locally sign using
:ref:`evmctl`.

A read policy rule will prevent a file from being read or executed if
the signature does not verify.

::

   appraise func=FILE_CHECK mask=^MAY_READ

Altering a signed file will invalidate the signature. To prevent
alteration, use a policy rule such as this. The appraise on write
prevents the signed file from being open for write. Without a write
policy rule, the file can be written but the signature becomes
invalid.

::

   appraise func=FILE_CHECK

|

.. _ima-audit:

IMA-Audit
===================================

IMA-Audit includes file hashes in the system audit log, which can be
used to augment existing system security
analytics and/or forensics. IMA-Audit extends the IMA policy ABI with the
:ref:`policy-syntax-action` keyword ``audit``.

There are no built-in policies containing audit rules.

Example policy to audit executable files and files open by user 10:

::

   audit func=BPRM_CHECK mask=MAY_EXEC
   audit func=FILE_CHECK mask=MAY_READ fowner=0

The system audit log is in the ``/var/log/audit`` directory.  The
entry will have ``type=INTEGRITY_RULE`` and the entry includes:

* file name
* hash algorithm and hash
* ppid, pid,
* auid, uid, gid, euid, suid, fsuid, egid, sgid, fsgid
* the command that triggered the rule

A typical audit log entry is (with newlines added for readability):

::

   type=INTEGRITY_RULE msg=audit(1724272003.040:450): file="/home/kgold/.emacs"
   hash="sha256:654897e5d6ff41bffac650f7f545975757380ae0bf1bb5459c0dc054cb342084"
   ppid=13236 pid=13396
   auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000
   tty=pts2 ses=2 comm="more" exe="/usr/bin/more"
   subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023AUID="kgold" UID="kgold"
   GID="kgold" EUID="kgold" SUID="kgold" FSUID="kgold" EGID="kgold" SGID="kgold" FSGID="kgold"


|


.. _ima-integrity-audit-events:

IMA Integrity Audit Events
===================================

Separate from :ref:`ima-audit`, IMA adds several integrity events
to the system audit log ``/var/log/audit/audit.log``.

Events that require a measure policy rule include:

* integrity violations 
* failure to extend the TPM PCR

Events that require an appraise policy rule include:

* failure to mmap a file
* failure to load or update a IMA policy

Events that require any policy rule include:

* failure to calculate a file hash

Events that occur independent of policy rules include:

* failure to calculate the boot_aggregate
* loading IMA policy rules

.. warning::

   TODO classify unsupported hash algorithms

**Integrity violations** include "open writers" or "Time of Measure /
Time of Use (ToMToU)". They are logged in the :ref:`template-hash`
field of the :ref:`ima-event-log`.

"Open writers" means a file was first open for write and now is open for
read, because the writer can write while the reader is doing a
measurement.

"Time of Measure / Time of Use" means a file was first open for read and
now is open for write, so the measured file can be modified.

An example of an open writers audit event is:

::

   type=INTEGRITY_PCR msg=audit(1721934216.094:1227): pid=3546 uid=0 auid=1000 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0 op=invalid_pcr cause=open_writers comm="grep" name="/var/log/audit/audit.log" dev="sda3" ino=21348467 res=1 errno=0UID="root" AUID="kgold"

**Failure to mmap a file** occurs when a file is first mmap'ed for
write and now is mmap'ed for execute.



|

.. _extended-verification-module:

Extended Verification Module (EVM)
===================================

EVM (Extended Verification Module) detects tampering of file
meta-data. :ref:`evm-hmac` is limited to off-line protection.
:ref:`evm-signature` can also protect against runtime tampering.

:ref:`evm-signature` aims at protecting files that are not expected to
change while the system is running. Examples are kernel modules, as
well as ELF and other binaries.

EVM appraises file meta-data and recurses from
the meta-data to the file data.  Since the meta-data includes
``security.ima``, the :ref:`evm-hmac` or :ref:`evm-signature` covers
both the data and  meta-data. First ``security.evm`` is
verified, followed by ``security.ima``.

The EVM extended attribute ``security.evm`` has two forms:

* :ref:`evm-hmac` generated locally across a set of file meta-data
* :ref:`evm-signature` generated locally (for testing only) or remotely.

The file meta-data does not include the file name. It therefore does
not protect against rename attacks (e.g., renaming mv to rm).

Specifically, appraisal covers this list of meta-data - extended
attributes and some inode meta-data.  The list is the same for
:ref:`evm-hmac` or :ref:`evm-signature`, but a ``portable signature``
excludes the last two items, which are installation specific.

  * ``security.ima``
  * ``security.selinux``
  * ``security.SMACK64``
  * ``security.SMACK64EXEC``
  * ``security.SMACK64TRANSMUTE``
  * ``security.SMACK64MMAP``
  * ``security.apparmor``
  * ``security.capability`` The capabilities associated with a superuser process.
  * uid, gid
  * mode (protections)
  * inode number (i_ino)
  * generation (i_generation)

``security.selinux`` is included when SELinux is enabled.

``security.SMACK64`` is included when SMACK is enabled. The other
SMACK attributes are added when :ref:`config-evm-extra-smack-xattrs`
is set.

``security.apparmor`` is included when AppArmor is enabled.

Additional security extended attributes can be included at runtime by
adding them to ``/sys/kernel/security/integrity/evm/evm_xattrs`` if
:ref:`config-evm-add-xattrs` is set.

.. warning::

   Needs a good example of an additional attribute.

The same :ref:`ima-appraisal` rules trigger EVM appraisal if EVM is
enabled.  See :ref:`evm-build-flags`.

Enabling EVM
-----------------------------------

The EVM extended attribute in ``security.evm`` can be
viewed with

::

   getfattr -m - -e hex -d <file>

.. warning::

   Test this:

   https://github.com/mgerstner/ima-inspect does further human
   readable printing of the extended attribute.

The pseudo-file ``/sys/kernel/security/integrity/evm/evm`` holds the
EVM status. The default is zero / off. The file is a bitmap with the
meaning:

===	  ================================================================================
Bit	  Effect
===	  ================================================================================
0	  Enable signature verification, HMAC verification and creation
1	  Enable signature verification
2	  Permit modification of EVM-protected meta-data at runtime.

          Not allowed if HMAC verification and creation is enabled.
31	  Disable further runtime modification of EVM state
          (``/sys/kernel/security/integrity/evm/evm``)
===	  ================================================================================

Before enabling :ref:`evm-hmac`, the EVM HMAC key must be in
``/etc/keys/evm-key``. The value can be set using a script enabled in
the dracut module ``modules.d/(nn)integrity/module-setup.sh``.  Before
enabling :ref:`evm-signature`, the EVM public key certificate must be
added to the :ref:`dot-evm` keyring.

There are no compile time or boot command line specifiers and no
equivalent to the IMA :ref:`boot-time-custom-policy`.  There is an
equivalent to the IMA :ref:`runtime-custom-policy`, writing a value
to ``/sys/kernel/security/integrity/evm/evm``.  For example:

::

   echo 1 > /sys/kernel/security/integrity/evm/evm

will enable signature verification, HMAC verification and
creation.

::

   echo 0x80000002 > /sys/kernel/security/integrity/evm/evm

will enable signature verification and disable all further run-time
modification of ``/sys/kernel/security/integrity/evm/evm``.

The lock, bit 31 (0x80000000), is useful when bit 1 (Signature only)
is set to block setting bit 0 (HMAC and signature).  This limits EVM
to verifying file signatures, without loading an HMAC key.

Echoing a value is additive; the new value is added to the existing
initialization flags. A bit cannot be cleared. For example, after

::

   echo 2 > /sys/kernel/security/integrity/evm/evm
   echo 1 > /sys/kernel/security/integrity/evm/evm

the resulting value will be 3.

   Note: While ``cat`` will show the value, the lock, bit 31, is not
   displayed.

.. _evm-hmac:

EVM HMAC
-----------------------------------

This is an HMAC-sha1 across a set of security extended attributes,
storing the HMAC as the extended attribute ``security.evm``.  The
HMAC format is:

* 0x02 - ``EVM_XATTR_HMAC``
* 20-byte HMAC-sha1 binary (fixed at SHA-1)

These steps generate an HMAC key. See
https://www.kernel.org/doc/html/latest/security/keys/trusted-encrypted.html
for instructions.

1. Generate a symmetric key, called the ``master key``, which is a ``trusted key`` type.
2. Wrap (encrypt) the ``master key`` with the TPM storage primary key.
3. Store the wrapped ``master key`` in the filesystem.
4. Generate an HMAC key.
5. Encrypt the HMAC key with the ``master key`` to create the ``encrypted key`` 
6. Store the ``encrypted key`` in the filesystem.

If :ref:`config-user-decrypted-data` is not set, the HMAC key is
generated from a random number.

If :ref:`config-user-decrypted-data` is set, the HMAC key can be
generated from a random number or a user provided value.

At boot:

1. Unseal (decrypt) the ``master key`` using the TPM.  The unseal
   typically does not currently use TPM authorization (password or PCR
   values).
2. Decrypt the HMAC key from the ``encrypted key`` using the ``master key``.

The HMAC key may be the same on multiple systems, which permits an
image to be signed once.  This HMAC key would be a user provided
value. However, this requires this HMAC key to be present on multiple
systems for verification.

* When in ``fix`` mode, the HMAC is updated on a read.

* When in ``enforce`` mode, the HMAC is checked on a read and updated
  on a write.

.. _evm-signature:

EVM Signature
-----------------------------------

When EVM asymmetric signature enforcement has been enabled, the
verification key (X.509 certificate) must be available on the
:ref:`dot-evm` keyring.

The signature format is:

* 0x03 (EVM_IMA_XATTR_DIGSIG)
* signature byte stream

A signature that includes the file inode and generation numbers is not
portable because they will differ on each platform. A ``portable
signature`` excludes them, permitting the file to be installed on
multiple platforms. The main use is to include the file data and
meta-data signature in a distro package.

|

.. _keyrings:

Keyrings
===================================

The below kernel keyrings affect IMA.

Adding keys to a keyring can be measured.  See
:ref:`config-ima-measure-asymmetric-keys`, :ref:`func-key-check`, and
the :ref:`keyrings-condition` condition.

Use :ref:`keyctl-show` to view the values


.. _`dot-builtin-trusted-keys`:

.builtin_trusted_keys
-----------------------------------

These keys (certificates) are compiled into the kernel and loaded at
boot time.

View using :ref:`keyctl-show`.

``.builtin_trusted_keys`` verify loading of:

* :ref:`dot-secondary-trusted-keys` certificates
* :ref:`dot-ima` certificates on the :ref:`dot-ima` keyring
* kernel modules
* kexec'd kernel images


.. _`dot-machine`:

.machine
-----------------------------------

and

.. _`dot-platform`:

.platform
-----------------------------------

The :ref:`dot-machine` and :ref:`dot-platform` keyrings hold Machine
Owner Keys (``MOK``). They provide separate, distinct keyrings for
platform trusted keys, which the kernel automatically populates during
initialization from values provided by the platform.

Additional ``MOK`` keys are registered using :ref:`mokutil`.  At boot
time, a one-time firmware (e.g. UEFI) menu prompts to accept the
registered keys. See :ref:`kernel-signing-key-generation` for a sample
procedure.

The :ref:`dot-machine` keyring has the ability to store only CA
certificates and put the rest on the :ref:`dot-platform` keyring,
separating the code signing keys from the keys that are used to sign
certificates. This unlocks the use of the :ref:`dot-machine` keyring
as a trust anchor for IMA.

If secure boot in the UEFI firmware is disabled (see
:ref:`sb-state`), keys are not loaded onto either the
:ref:`dot-machine` or :ref:`dot-platform` keyring.

if :ref:`config-integrity-platform-keyring` is clear, keys are not
loaded onto either the :ref:`dot-machine` or :ref:`dot-platform` keyring.

Otherwise,if the UEFI variables MokListRT/ MokListXRT are clear,
registered keys are loaded on the :ref:`dot-platform` keyring.

Otherwise, if :ref:`config-integrity-ca-machine-keyring-max` is set, only
registered CA signing key certificates (X.509 CA bit and keyCertSign
true, and digitalSignature false) are loaded on the :ref:`dot-machine`
keyring. The rest are loaded on the :ref:`dot-platform` keyring.

Otherwise, if :ref:`config-integrity-ca-machine-keyring` is set, only
the registered signing key certificates (X.509 CA bit and keyCertSign
true) are loaded on the :ref:`dot-machine` keyring. The remainder are
loaded on the :ref:`dot-platform` keyring.

Otherwise, if :ref:`config-integrity-machine-keyring` is set, all the
registered ``MOK`` keys are loaded on the :ref:`dot-machine` keyring.

Otherwise, the keys are loaded on the :ref:`dot-platform` keyring.

The :ref:`dot-machine` keyring can only be enabled if
:ref:`config-secondary-trusted-keyring` and
:ref:`config-integrity-machine-keyring` are set.

These keys are loaded on the :ref:`dot-machine` or :ref:`dot-platform`
keyring:

* UEFI - Secure Boot ``db`` keys, excluding ``dbx`` keys
* Machine owner (MOK) keys if secure boot is enabled
* PowerPC - platform and deny listed keys for POWER
* S390 - IPL keys

:ref:`dot-machine` keys verify loading of

* kernel modules
* kexec'd kernel images
* :ref:`dot-secondary-trusted-keys` certificates
* :ref:`dot-ima` certificates on the :ref:`dot-ima` keyring

:ref:`dot-platform` keys verify loading of

* kernel modules (for some downstream distros)
* kexec'd kernel images

.. _dot-secondary-trusted-keys:

.secondary_trusted_keys
-----------------------------------

These keys (certificates) are signed by a key on the
:ref:`dot-builtin-trusted-keys`, :ref:`dot-machine`, or
:ref:`dot-secondary-trusted-keys` keyring.

They are loaded using :ref:`keyctl`.

View using :ref:`keyctl-show`.

``.secondary_trusted_keys`` verify loading of:

* other :ref:`dot-secondary-trusted-keys` certificates
* :ref:`dot-ima` certificates on the :ref:`dot-ima` keyring
* kernel modules
* kexec'd kernel images

.. _`dot-ima`:

.ima
-----------------------------------

Only certificates signed by a key on the
:ref:`dot-builtin-trusted-keys`, :ref:`dot-secondary-trusted-keys`, or
:ref:`dot-machine` keyrings may be loaded onto the ``.ima`` keyring.

``.ima`` keys are loaded from ``/etc/keys/ima`` at boot time using a
dracut script ``modules.d/(nn)integrity/ima-keys-load.sh`` calling
:ref:`keyctl`. They cannot be compiled into the kernel. If the script
is absent, keys will not automatically be loaded.

Keys on the ``.ima`` keyring are used for

* :ref:`ima-appraisal`

The key used for verification is based on the :ref:`public-key-identifier`.

.. _`dot-evm`:

.evm
-----------------------------------

Only certificates signed by a key on the
:ref:`dot-builtin-trusted-keys` or :ref:`dot-secondary-trusted-keys`
keyrings may be loaded onto the ``.evm`` keyring.

``.evm`` keys are loaded from ``/etc/keys/x509_evm.der`` at boot time
using a dracut script calling :ref:`evmctl`. They cannot be compiled
in. Additional keys can be loaded at runtime using :ref:`evmctl`.

Keys on the ``.evm`` keyring are used for

* :ref:`evm-signature` verification.

The key used for verification is based on the :ref:`public-key-identifier`.

.. _dot-blacklist:

.blacklist
-----------------------------------

The ``.blacklist`` keyring holds keys and hashes that are not approved
/ have been revoked.

This keyring is initially populated from a revocation list. A key on
``.blacklist`` cannot be added to another keyring and cannot be used
to verify another key or file :ref:`evm-signature`.

The revocation keys comes from:

* UEFI - DBX
* Power - platform and deny listed keys for POWER
* S390 -  IPL keys

``.blacklist`` also contain a file data :ref:`hash` that is not
approved.

See :ref:`config-system-blacklist-keyring` and :ref:`appraise-flag`.

|

kexec Implications
===================================

kexec Background
-----------------------------------

kexec is a soft boot. The command boots a new kernel image with new
command line arguments. It does not cycle back to the hardware
initialization typically performed by platform firmware.

The policy rules are set by the new
:ref:`kernel-configuration-options` and
:ref:`boot-command-line-arguments`.

.. _kexec-ima-impact:

kexec IMA Impact
-----------------------------------

Since the hardware is not initialized, the TPM PCRs, and specifically
the IMA PCR, are not reset back to zeros.  Therefore, an attestation
will include the PCR extends from the previous kernel boot as well as
the new kernel boot. In order for the verifier to validate the IMA PCR
against the IMA event log, it must be presented with both the previous
and current event logs. The previous event log must be carried across
the kexec boot.

:ref:`config-ima-kexec` enables the event log to be retained across a
kexec. If the event log is not retained, PCR 10 cannot provide event
log integrity.

   Note: Even if the event log is retained, the image load copies the
   event log, but the new image is not executed atomically with the
   load. All measurements that may occur between the kexec load and
   execute are lost, and therefore the measurement log may not match
   PCR 10. Validation of the two may fail once the new kernel is
   running.

   If no measurement log appends occur after the kexec load,
   validation will succeed.

Carrying the previous event log through a kexec reboot will increase
the size of the in-memory log.  See :ref:`measure-policy-rule-design`.




kexec IMA Configuration
-----------------------------------

These items affect kexec measure and appraisal:

* The event log field :ref:`buf` and the policy rule
  :ref:`func-kexec-cmdline`.

To support kexec verification, the IMA :ref:`template-data-fields`
should include ``buf``, which records the kexec command line
arguments.

* :ref:`config-ima-kexec`

This kernel configuration flag enables carrying the IMA event log
across a soft boot (kexec).  Since the TPM IMA PCR does not get reset
upon kexec, the verifier requires both the pre- and post-kexec event
logs.

* :ref:`func-kexec-kernel-check`

This policy rule measures or appraises the kexec kernel image. See
:ref:`func-kexec-kernel-check` for the rule syntax.

* :ref:`func-kexec-initramfs-check`

This policy rule measures or appraises the kexec initramfs image.  See
:ref:`func-kexec-initramfs-check` for the rule syntax.

* :ref:`func-kexec-cmdline`

This policy rule measures the kexec boot command line. See
:ref:`func-kexec-cmdline` for the rule syntax.

|

.. _appended-signatures:

Appended Signatures
===================================

Appended signatures are an alternative to signatures in extended
attributes or the pecoff header.

Appended signatures support these appraise policy rules:

* kernel modules - see :ref:`func-module-check`
* kernel images - see :ref:`func-kexec-kernel-check`
* initramfs - see :ref:`func-kexec-initramfs-check`

Appended signatures are not supported for the :ref:`func-file-check`
rule.

A file can have both an appended signature and an extended attribute
signature. Since the extended attribute signature signs the entire
file, it must be calculated after the appended signature is added.

   Use case: A distro can apply an appended signature.  An enterprise
   can further lock down their platform by applying an extended
   attribute signature using their enterprise signing key.

To verify whether an appended signature file is present, ``tail`` the
file. The  content is binary, but the string ``Module signature appended~``
is appended.

For a compressed kernel module, see the :ref:`xz` function.


