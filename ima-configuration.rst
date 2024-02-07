.. toctree::
   :maxdepth: 8
   :caption: IMA Configuration:

===================
IMA Configuration
===================

Kernel Support
===================================

IMA is now compiled in by most distros.  See the build flag
CONFIG_IMA_. Known distros are:

* Fedora
* CentOS
* RHEL
* Ubuntu
* Debian
* Alpine
* OpenSuse
* AltLinux
* Gentoo

Configuration takes three forms:

* :ref:`build-flags`
* :ref:`boot-command-line-arguments`
* :ref:`custom-policy`

.. _build-flags:

Build Flags
===================================

Linux build flags are options that are passed to the compiler when
building the kernel.

The state of build flags can be viewed with, e.g.,

::

   cat /boot/config-`uname -r` | grep IMA_WRITE_POLICY

The boolean values are

* "=y" if compiled statically into the kernel
* "=m" if compiled in as a kernel module
* "is not set" if that setting was commented out
* not listed is the same as commented out

Relevant build flags are in
https://github.com/torvalds/linux/blob/master/security/integrity/ima/Kconfig

:ref:`general-build-flags`:

* :ref:`config-integrity`
* :ref:`config-ima`
* :ref:`config-ima-write-policy`
* :ref:`config-ima-read-policy`
* :ref:`config-ima-default-hash`
* :ref:`config-fs-verity`

:ref:`compiled-in-policies`:

* :ref:`config-ima-arch-policy`
* :ref:`config-ima-appraise-build-policy`
* :ref:`config-ima-appraise-require-firmware-sigs`
* :ref:`config-ima-appraise-require-kexec-sigs`
* :ref:`config-ima-appraise-require-module-sigs`
* :ref:`config-ima-appraise-require-policy-sigs`

:ref:`measure`:

* :ref:`config-ima-default-template`
* :ref:`config-ima-measure-pcr-idx`
* :ref:`config-ima-kexec`
* :ref:`config-ima-disable-htable`
* :ref:`config-ima-measure-asymmetric-keys`
* :ref:`config-ima-lsm-rules`
* :ref:`config-ima-queue-early-boot-keys`

:ref:`appraise`:

* :ref:`config-ima-appraise`
* :ref:`config-ima-appraise-bootparam`
* :ref:`config-ima-appraise-modsig`
* :ref:`config-ima-trusted-keyring`
* :ref:`config-integrity-signature`
* :ref:`config-integrity-asymmetric-keys`
* :ref:`config-ima-appraise-signed-init`
* :ref:`config-system-blacklist-keyring`
* :ref:`config-load-uefi-keys`
* :ref:`config-load-ipl-keys`
* :ref:`config-load-ppc-keys`

:ref:`evm-build-flags`:

* :ref:`config-evm`
* :ref:`config-encrypted-keys`
* :ref:`config-user-decrypted-data`
* :ref:`config-trusted-keys`
* :ref:`config-evm-add-xattrs`
* :ref:`config-evm-extra-smack-xattrs`

:ref:`keyring-configuration`:

* :ref:`config-secondary-trusted-keyring`
* :ref:`config-integrity-platform-keyring`
* :ref:`config-integrity-machine-keyring`
* :ref:`config-integrity-ca-machine-keyring`

.. _general-build-flags:

General
-----------------------------------

* CONFIG_INTEGRITY_
* CONFIG_IMA_
* :ref:`config-ima-write-policy`
* :ref:`config-ima-read-policy`
* :ref:`config-ima-default-hash`
* :ref:`config-fs-verity`

.. _config-integrity:

CONFIG_INTEGRITY
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables the integrity subsystem, which includes the
Integrity Measurement Architecture (IMA), Extended Verification Module
(EVM), the IMA-appraisal extension, the digital signature verification
extension and audit measurement log support.

Each of these components can be enabled/disabled separately.
Refer to the individual components for additional details.

* IMA - see :ref:`config-ima`.
* EVM - see :ref:`config-evm`.
* IMA Appraisal Hash verification - see :ref:`config-ima-appraise`
* IMA Appraisal Digital Signature Verification - see :ref:`config-integrity-signature`.
* audit measurement log support.

.. _config-ima:

CONFIG_IMA
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables IMA.

.. _config-ima-write-policy:

CONFIG_IMA_WRITE_POLICY
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables multiple appends to the custom IMA policy. See
:ref:`runtime-custom-policy`.

.. _config-ima-read-policy:

CONFIG_IMA_READ_POLICY
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables reading the current IMA policy.  See
:ref:`reading-policies`.  This option allows the root user to see the
current policy rules.

If the boolean is false, either the policy file will not exist or the
policy file will exist but the mode bits will not permit a read.

.. _config-ima-default-hash:

CONFIG_IMA_DEFAULT_HASH
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This string specifies the file data hash algorithm for measurement,
appraisal, and audit. It is overridden by the
:ref:`boot-command-line-arguments` :ref:`ima-hash` specifier. Both can
be overridden by the hash used for the file signature algorithm.

Supported values are:

* ``sha1``
* ``sha256``
* ``sha512``
* ``wp512``
* ``sm3``

.. _config-fs-verity:

CONFIG_FS_VERITY
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables ``fs-verity`` read-only file-based authenticity protection.

.. _compiled-in-policies:

Compiled-In Policies
-----------------------------------

Build flags can specify appraisal policy rules that are present at run
time if the :ref:`boot-command-line-arguments` are not used.

These are:

* :ref:`config-ima-arch-policy`
* :ref:`config-ima-appraise-build-policy`
* :ref:`config-ima-appraise-require-firmware-sigs`
* :ref:`config-ima-appraise-require-kexec-sigs`
* :ref:`config-ima-appraise-require-module-sigs`
* :ref:`config-ima-appraise-require-policy-sigs`

The rules determined by :ref:`config-ima-arch-policy` persist - are
not replaced.  The other flags determine rules that can be replaced.

.. _config-ima-arch-policy:

CONFIG_IMA_ARCH_POLICY
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables compiled-in architecture specific policy
rules. If enabled, it loads its IMA appraise rules before other
compiled-in or built-in command line appraise rules, so they cannot be
overridden.  They persist.  I.e., they cannot be replaced by a
:ref:`boot-time-custom-policy` or :ref:`runtime-custom-policy`, which
might otherwise remove these rules.

Secure boot must appraise the entire boot software
stack through the kernel. This includes the kernel kexec image and
kernel modules. The kernel configuration includes a method using
``CONFIG_KEXEC_SIG`` and ``CONFIG_MODULE_SIG``.  If either is not
enabled, IMA verifies (appraises) the signatures.

That is, if ``CONFIG_KEXEC_SIG`` is true, the kernel will require and
verify the signature over the kernel image.  If false,
``CONFIG_IMA_ARCH_POLICY`` will add an IMA appraise 
:ref:`func-kexec-kernel-check` rule.

If ``CONFIG_MODULE_SIG`` is true, the kernel will verify a kernel
module appended signature. If false, ``CONFIG_IMA_ARCH_POLICY`` will
add an IMA appraise :ref:`func-module-check` rule.

In addition to the appraise rules, ``CONFIG_IMA_ARCH_POLICY``
always adds trusted boot measure rules for :ref:`arm-and-x86` UEFI
based platforms.

These policy rules are based on the firmware boot status
(e.g. :ref:`arm-and-x86` UEFI secure boot, :ref:`powerpc` secure boot
and trusted boot). See :ref:`secure-boot-state` for a method of
determining whether secure and/or trusted boot is enabled.


.. _arm-and-x86:

ARM and x86
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. warning::

   **FIXME test this**

If UEFI secure boot is enabled:

If ``CONFIG_KEXEC_SIG`` is false, ``CONFIG_IMA_ARCH_POLICY`` adds this
rule to appraise the kernel:

::

   appraise func=KEXEC_KERNEL_CHECK appraise_type=imasig

If ``CONFIG_MODULE_SIG`` is false, ``CONFIG_IMA_ARCH_POLICY`` adds
this rule to appraise kernel modules:

::

   appraise func=MODULE_CHECK appraise_type=imasig

Regardless of those configuration flags, ``CONFIG_IMA_ARCH_POLICY``
adds these rules to measure the kernel and kernel modules.  It does
not differentiate between secure and trusted boot.

::

   measure func=KEXEC_KERNEL_CHECK
   measure func=MODULE_CHECK

.. _powerpc:

PowerPC
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If firmware secure boot is enabled, ``CONFIG_IMA_ARCH_POLICY`` adds
this rule:

::

    appraise func=KEXEC_KERNEL_CHECK appraise_flag=check_blacklist appraise_type=imasig|modsig

and if ``CONFIG_MODULE_SIG`` is false, ``CONFIG_IMA_ARCH_POLICY`` adds
this rule

::

    appraise func=MODULE_CHECK appraise_flag=check_blacklist appraise_type=imasig|modsig

If only trusted boot is enabled, ``CONFIG_IMA_ARCH_POLICY`` adds these
rules:

::

    measure func=KEXEC_KERNEL_CHECK
    measure func=MODULE_CHECK

If both firmware secure boot and trusted boot are enabled,
``CONFIG_IMA_ARCH_POLICY`` adds these rules:

::

    measure func=KEXEC_KERNEL_CHECK template=ima-modsig
    measure func=MODULE_CHECK template=ima-modsig
    appraise func=KEXEC_KERNEL_CHECK appraise_flag=check_blacklist appraise_type=imasig|modsig

and if ``CONFIG_MODULE_SIG`` is false, ``CONFIG_IMA_ARCH_POLICY`` adds
this rule

::

    appraise func=MODULE_CHECK appraise_flag=check_blacklist appraise_type=imasig|modsig

.. _config-module-sig:

CONFIG_MODULE_SIG
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables an alternative method (not IMA) for validating
 appended signatures.

See :ref:`config-ima-arch-policy`.

.. _config-ima-appraise-build-policy:

CONFIG_IMA_APPRAISE_BUILD_POLICY
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables compiled-in IMA policy rules. They are effective
at runtime without needing an :ref:`ima-policy` on the boot
command line.  It loads its IMA appraise rules before other
compiled-in or built-in command line appraise rules.  Unlike
:ref:`config-ima-arch-policy`, these rules can be replaced by a
:ref:`boot-time-custom-policy` or :ref:`runtime-custom-policy`.

If enabled
:ref:`config-ima-appraise-require-firmware-sigs`,
:ref:`config-ima-appraise-require-kexec-sigs`,
:ref:`config-ima-appraise-require-module-sigs`, and
:ref:`config-ima-appraise-require-policy-sigs`
determine the policy rules.

An alternative to the compiled-in policy rules is
:ref:`ima-policy-secure-boot` on the boot command line.

.. _config-ima-appraise-require-firmware-sigs:

CONFIG_IMA_APPRAISE_REQUIRE_FIRMWARE_SIGS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables a policy rule to appraise
firmware. :ref:`config-ima-appraise-build-policy` enables this
flag.

It requires all firmware to be signed.  See :ref:`func` and
:ref:`appraise-type`.

::

   appraise func=FIRMWARE_CHECK appraise_type=imasig

.. _config-ima-appraise-require-kexec-sigs:

CONFIG_IMA_APPRAISE_REQUIRE_KEXEC_SIGS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables a policy rule to appraise kexec'ed kernel
images. :ref:`config-ima-appraise-build-policy` enables this flag.

It requires all kexec'ed kernel images to be signed and verified by a
public key on the trusted IMA keyring. See :ref:`func` and
:ref:`appraise-type`.

::

   appraise func=KEXEC_KERNEL_CHECK appraise_type=imasig

.. _config-ima-appraise-require-module-sigs:

CONFIG_IMA_APPRAISE_REQUIRE_MODULE_SIGS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables a policy rule to appraise kernel module
signatures.  :ref:`config-ima-appraise-build-policy` enables this
flag.

It requires all kernel modules to be signed and verified
by a public key on the trusted IMA keyring.  See :ref:`func` and
:ref:`appraise-type`.

::

   appraise func=MODULE_CHECK appraise_type=imasig

.. _config-ima-appraise-require-policy-sigs:

CONFIG_IMA_APPRAISE_REQUIRE_POLICY_SIGS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables a policy rule to appraise IMA policy
signatures. :ref:`config-ima-appraise-build-policy` enables this
flag.

It requires the IMA policy to be signed and verified
by a key on the trusted IMA keyring.See :ref:`func`, 
:ref:`appraise-type`, and :ref:`custom-policy`.

::

    appraise func=POLICY_CHECK appraise_type=imasig



.. _measure:

Measure
-----------------------------------

The configuration flags affecting measurement are below.  See :ref:`policy-rule-order`.

* :ref:`config-ima-default-template`
* :ref:`config-ima-measure-pcr-idx`
* :ref:`config-ima-kexec`
* :ref:`config-ima-disable-htable`
* :ref:`config-ima-measure-asymmetric-keys`
* :ref:`config-ima-lsm-rules`
* :ref:`config-ima-queue-early-boot-keys`

.. _config-ima-default-template:

CONFIG_IMA_DEFAULT_TEMPLATE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This string sets the default value for the :ref:`ima-event-log`
:ref:`built-in-templates`, which specifies the IMA event log format.

The default value can be globally overridden by the
:ref:`boot-command-line-arguments` :ref:`template-specifiers`.  They
can be overridden for a measurement by a :ref:`policy-syntax`
:ref:`template`.

The value depends upon the kernel release.  A typical value is
:ref:`ima-ng` or :ref:`ima-sig`.


.. _config-ima-measure-pcr-idx:

CONFIG_IMA_MEASURE_PCR_IDX
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This decimal number sets the PCR index used by IMA.  The default is 10.

See also the policy rule :ref:`pcr-value`.

.. _config-ima-kexec:

CONFIG_IMA_KEXEC
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables carrying the IMA measurement list across a kexec
soft boot.

TPM PCRs are only reset on a hard reboot.  In order to validate a
TPM's quote after a soft boot, the IMA measurement list of the running
kernel must be saved and restored after the soft boot.

Depending on the IMA policy, the measurement list can grow to
be very large.

.. _config-ima-disable-htable:

CONFIG_IMA_DISABLE_HTABLE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean affects measurement behavior. In detail, there are three
factors:

#. IMA status booleans, which indicate that the file has been opened
   for change since the last IMA measurement
#. The IMA hash table, which tracks files already measured
#. This kernel configuration flag CONFIG_IMA_DISABLE_HTABLE

The boolean is based on ``iversion`` for filesystems mounted with
``iversion``. Without ``iversion``, it is assumed that the file
changed.

NOTE: So that IMA will process the same hash again when seen in
different contexts, there are several boolean status bits:

* ima_file
* ima_mmap
* ima_bprm
* ima_read
* ima_cred
* evm

.. warning::

   Add a definition of each status bit.  Add cross references.
   How can the status bits be read?

In kernels that do not implement CONFIG_IMA_DISABLE_HTABLE, or if
CONFIG_IMA_DISABLE_HTABLE is false, if the status is true and the file hash is
not in the hash table, the file is measured. If the status is false (not
changed) or the hash is in the hash table (already measured), the file
is not measured.

The action is different if CONFIG_IMA_DISABLE_HTABLE is true. In this
case, if the status is true, the file is measured, even if the hash is
already in the hash table.

The intent of CONFIG_IMA_DISABLE_HTABLE true is to record the case
where a file changed, but changed back before it triggered a measure
policy. For example, if a file changed from hash1 to hash2 to hash1,
three events would be measured. If CONFIG_IMA_DISABLE_HTABLE was
false, the third event would not be measured, since hash1 was already
in the hash table. An attester, in the latter case, would think the
file was still in the hash2 state.

.. _config-ima-measure-asymmetric-keys:

CONFIG_IMA_MEASURE_ASYMMETRIC_KEYS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables measuring asymmetric keys when the key is loaded
onto a keyring. IMA policy rules can either measure keys loaded onto
any keyring or only measure keys loaded onto :ref:`keyrings` specified
through the :ref:`keyrings-condition` condition.

Examples:

* measure keys loaded onto any keyring

  ::

	measure func=KEY_CHECK

* measure keys loaded onto the :ref:`dot-ima` keyring only for the
  root user

  ::

	measure func=KEY_CHECK uid=0 keyrings=.ima

* measure keys on the :ref:`dot-builtin-trusted-keys` and
  :ref:`dot-ima` keyrings into a different PCR

  ::

	measure func=KEY_CHECK keyrings=".builtin_trusted_keys|.ima" pcr=11

.. _config-ima-lsm-rules:

CONFIG_IMA_LSM_RULES
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables policy rules containing LSM labels.

See :ref:`obj-user-equals`, :ref:`obj-role-equals`,
:ref:`obj-type-equals`, :ref:`subj-user-equals`,
:ref:`subj-role-equals` , and :ref:`subj-type-equals` for the policy
rule syntax.

If this boolean is disabled, a policy containing these policy rules
will be rejected.  See :ref:`runtime-custom-policy`.

.. _config-ima-queue-early-boot-keys:

CONFIG_IMA_QUEUE_EARLY_BOOT_KEYS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:ref:`built-in-policy-rules` do not have rules to measure keys added
to :ref:`keyrings`.  I.e., they do not have a :ref:`func-key-check`
rule.

When this boolean is set, keys added to keyrings at boot are queued.
When a :ref:`custom-policy` with a :ref:`func-key-check` rule is
specified, the queue is replayed so that each key can be measured.

.. _appraise:

Appraise
-----------------------------------

The configuration flags affecting appraisal are below.  See :ref:`policy-rule-order`.

* :ref:`config-ima-appraise`
* :ref:`config-ima-appraise-bootparam`
* :ref:`config-ima-appraise-modsig`
* :ref:`config-ima-trusted-keyring`
* :ref:`config-integrity-signature`
* :ref:`config-integrity-asymmetric-keys`
* :ref:`config-ima-appraise-signed-init`
* :ref:`config-system-blacklist-keyring`
* :ref:`config-load-uefi-keys`
* :ref:`config-load-ipl-keys`
* :ref:`config-load-ppc-keys`

.. _config-ima-appraise:

CONFIG_IMA_APPRAISE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables verifying local file integrity.

The default is ``enforce`` mode.  See
:ref:`config-ima-appraise-bootparam` and :ref:`ima-appraise` for
options.

See also :ref:`config-evm`.


.. _config-ima-appraise-bootparam:

CONFIG_IMA_APPRAISE_BOOTPARAM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean allows the different :ref:`ima-appraise` modes to be
specified on the boot command line.

False prevents disabling ``enforce`` mode on the boot command line for
a production system.

True allows ``enforce`` mode to be disabled on the boot command line
for debug or fixing hashes.

.. _config-ima-appraise-modsig:

CONFIG_IMA_APPRAISE_MODSIG
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean adds support for signatures appended to files. The format of the
appended signature is the same as that used for signed kernel modules.  The
``modsig`` keyword can be as used in the IMA policy to allow a hook to accept
such signatures.

See the policy rule :ref:`appraise-type` ``modsig``.


.. _config-ima-trusted-keyring:

CONFIG_IMA_TRUSTED_KEYRING
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables use of the trusted :ref:`dot-ima` and :ref:`dot-evm`
keyrings, as opposed to the ``_ima`` and ``_evm`` keyrings.


.. _config-integrity-signature:

CONFIG_INTEGRITY_SIGNATURE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables signature verification. See
:ref:`config-integrity-asymmetric-keys`.


.. _config-integrity-asymmetric-keys:

CONFIG_INTEGRITY_ASYMMETRIC_KEYS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables asymmetric key verification using asymmetric keys
on the :ref:`keyrings`.

See also :ref:`config-integrity-signature`.

.. _config-ima-appraise-signed-init:

CONFIG_IMA_APPRAISE_SIGNED_INIT
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean causes the built-in :ref:`ima-policy-appraise-tcb` to load
a policy rule requiring all root owned files be signed, as opposed to
being hashed.

.. _config-system-blacklist-keyring:

CONFIG_SYSTEM_BLACKLIST_KEYRING
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When this boolean is set, the :ref:`dot-blacklist` keyring is checked
before keys can be loaded onto :ref:`keyrings`.

.. _config-load-uefi-keys:

CONFIG_LOAD_UEFI_KEYS 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When this boolean is set, the :ref:`dot-platform` keyring is
provisioned with keys from the UEFI DB and the :ref:`dot-blacklist`
keyring is provisioned with keys from the UEFI DBX.


.. _config-load-ipl-keys:

CONFIG_LOAD_IPL_KEYS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When this boolean is set, the :ref:`dot-platform` keyring and the
:ref:`dot-blacklist` keyring are provisioned for S390.


.. _config-load-ppc-keys:

CONFIG_LOAD_PPC_KEYS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When this boolean is set, the :ref:`dot-platform` keyring and the
:ref:`dot-blacklist` keyring are provisioned for POWER.


.. _evm-build-flags:

EVM Build Flags
-----------------------------------

The configuration flags affecting EVM are below:

* :ref:`config-evm`
* :ref:`config-encrypted-keys`
* :ref:`config-user-decrypted-data`
* :ref:`config-trusted-keys`
* :ref:`config-evm-add-xattrs`
* :ref:`config-evm-extra-smack-xattrs`
  
  
.. _config-evm:

CONFIG_EVM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables EVM appraisal of extended attributes and file
meta-data.

See :ref:`extended-verification-module`.

.. _config-encrypted-keys:

CONFIG_ENCRYPTED_KEYS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This tristate enables :ref:`evm-hmac`.

It can be set to either '``y`` (built in to the kernel)
or ``m`` if compiled as a kernel module.  ``y`` is
desired.


.. _config-user-decrypted-data:

CONFIG_USER_DECRYPTED_DATA
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean permits the user to instantiate the :ref:`evm-hmac` ``encrypted key``
with user-provided decrypted data using :ref:`keyctl`.

If not set, the kernel uses a random number.

It requires :ref:`config-encrypted-keys`.

See https://www.kernel.org/doc/html/latest/security/keys/trusted-encrypted.html

.. warning::

   Add an example of keyctl.

.. _config-trusted-keys:

CONFIG_TRUSTED_KEYS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This tristate enables the generation and load of a :ref:`evm-hmac` ``master key``.
This is a ``trusted key`` type.

It can be set to either '``y`` (built in to the kernel)
or ``m`` if compiled as a kernel module.  ``y`` is
desired.

It requires :ref:`config-encrypted-keys`.

See https://www.kernel.org/doc/html/latest/security/keys/trusted-encrypted.html

.. _config-evm-add-xattrs:

CONFIG_EVM_ADD_XATTRS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean permits the user to add additional EVM extended
attributes (xattrs) at runtime.

When this option is enabled, root can add additional xattrs to the
list used by EVM by writing them into
``/sys/kernel/security/integrity/evm/evm_xattrs``.

See :ref:`extended-verification-module` for the default list.

.. _config-evm-extra-smack-xattrs:

CONFIG_EVM_EXTRA_SMACK_XATTRS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean adds additional SMACK EVM extended attributes (xattrs)
for the HMAC calculation.  It adds:

* ``security.SMACK64EXEC``
* ``security.SMACK64TRANSMUTE``
* ``security.SMACK64MMAP``

.. _keyring-configuration:

Keyring Configuration
-----------------------------------


The configuration flags affecting trusted :ref:`keyrings` are:

* :ref:`config-secondary-trusted-keyring`
* :ref:`config-integrity-platform-keyring`
* :ref:`config-integrity-machine-keyring`
* :ref:`config-integrity-ca-machine-keyring`
* :ref:`config-integrity-ca-machine-keyring-max`

.. _config-secondary-trusted-keyring:

CONFIG_SECONDARY_TRUSTED_KEYRING
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables the :ref:`dot-secondary-trusted-keys` keyring to
which extra keys may be added, provided those keys are not on a deny
list and are vouched for by a key built into the kernel, a key on the
:ref:`dot-machine` keyring, or a key already in the
:ref:`dot-secondary-trusted-keys` keyring.

.. _config-integrity-platform-keyring:

CONFIG_INTEGRITY_PLATFORM_KEYRING
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This boolean enables the :ref:`dot-platform` keyring.

.. _config-integrity-machine-keyring:

CONFIG_INTEGRITY_MACHINE_KEYRING
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When this boolean is set, registered machine owner key certificates
are loaded by default on the :ref:`dot-machine` keyring.

When it is clear, registered machine owner key certificates are loaded
on the :ref:`dot-platform` keyring.

   Note that this boolean is only supported for ``MOK`` keys on UEFI.

:ref:`config-integrity-ca-machine-keyring` and
:ref:`config-integrity-ca-machine-keyring-max` can override the
default.


.. _config-integrity-ca-machine-keyring:

CONFIG_INTEGRITY_CA_MACHINE_KEYRING
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When this boolean is set, registered ``MOK`` key signing certificates
(X.509 CA bit and keyCertSign true) are loaded on the
:ref:`dot-machine` keyring. Others go on the :ref:`dot-platform`
keyring.

See also :ref:`config-integrity-ca-machine-keyring-max`.

======================  ===================================
Distribution		State
----------------------  -----------------------------------
Ubuntu 23		not set
----------------------  -----------------------------------
Fedora 39		set
======================  ===================================

.. _config-integrity-ca-machine-keyring-max:

CONFIG_INTEGRITY_CA_MACHINE_KEYRING_MAX  
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When this boolean is set, registered ``MOK`` key signing CA
certificates (X.509 CA bit and keyCertSign true, and digitalSignature
false) are loaded on the :ref:`dot-machine` keyring. Others go on the
:ref:`dot-platform` keyring.

This boolean overrides :ref:`config-integrity-ca-machine-keyring`.

======================  ===================================
Distribution		State
----------------------  -----------------------------------
Ubuntu 23		not set
----------------------  -----------------------------------
Fedora 39		set
======================  ===================================


.. _boot-command-line-arguments:

Boot Command Line Arguments
===================================

These boot command line arguments can be added on the boot command line.

* :ref:`ima-hash`
* :ref:`ima-policy`
* :ref:`ima-appraise`
* :ref:`ima-template`
* :ref:`ima-canonical-fmt`
* :ref:`ima-template-fmt`

.. _hash-specifiers:

Hash Specifiers
-----------------------------------

.. _ima-hash:

ima_hash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``ima_hash=`` argument specifies the file data hash algorithm
used.  It overrides the :ref:`config-ima-default-hash` algorithm.

* measurement - the :ref:`ima-event-log` - :ref:`template-data-fields`
  - :ref:`d-ng` and :ref:`d-ngv2` hash algorithm

* appraisal - the hash algorithm used to calculate and verify hashes

* audit - the hash algorithm used for audit log entries

Supported values are:

* ``md5``	supported only for :ref:`ima-template` =ima
* ``sha1``	:ref:`ima-template` =ima default
* ``sha224``
* ``sha256``	default
* ``sha384``
* ``sha512``
* ``rmd128``
* ``rmd160``
* ``rmd256``
* ``rmd320``
* ``wp256``
* ``wp384``
* ``wp512``
* ``tgr128``
* ``tgr160``
* ``tgr192``
* ``sm3``
* ``streebog256``
* ``streebog512``

If :ref:`ima-template` is ``ima``, only ``md5`` and ``sha1`` are
supported.

The values are taken from
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/crypto/hash_info.c.

.. _policy-specifiers:

Policy Specifiers
-----------------------------------

.. _ima-policy:

ima_policy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``ima_policy=`` argument specifies boot time IMA policy rules.
There are several :ref:`built-in-policy-rules`. Selecting an IMA built-in
policy uses those formats.  See :ref:`built-in-policy-rules` for their
effect.

The command line arguments ``ima_tcb`` and ``ima_appraise_tcb`` are
deprecated in favor of :ref:`ima-policy-tcb` and
:ref:`ima-policy-appraise-tcb`.

Multiple ``ima_policy`` specifiers can be used.  Their policies are
concatenated.  The order is hard coded as shown in the below list.

The supported measure values for ``ima_policy=`` are:

1. :ref:`ima-policy-tcb` - measure rules
2. :ref:`ima-policy-critical-data` - measure rules

The supported appraise values for ``ima_policy=`` are:

1. :ref:`ima-policy-secure-boot`
2. :ref:`ima-policy-appraise-tcb`
3. :ref:`ima-policy-fail-securely`

The two ways of using multiple specifiers are:

* Multiple ``ima_policy=`` statements.  For example:

::

  ima_policy=tcb ima_policy=critical_data

* Multiple specifiers using this divider line format.  For example

::

  ima_policy="tcb|critical_data"

This divider line format requires the terms to be in ``"``.  One
can either edit the boot command line interactively or edit the grub
boot file, e.g., ``/boot/loader/entries`` on Fedora.  The
``grubby --args=`` method cannot be used because grubby does not
parse the ``|`` or the ``"`` correctly.

.. _appraise-specifiers:

Appraise Specifiers
-----------------------------------

.. _ima-appraise:

ima_appraise
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``ima_appraise=`` argument can change the default ``enforce``
appraise mode.

**Note**: The mode can only be changed if secure boot in the UEFI
firmware is disabled. If UEFI secure boot is enabled, the default
``enforce`` cannot be changed.  See :ref:`built-in-policy-rules`.  This is
**not** the same as the :ref:`ima-policy-secure-boot` command line
argument.

This command line argument is only available if
:ref:`config-ima-appraise-bootparam` is set.

This specifies the effect of the policy rule ``appraise`` action. The four values are:

* ``enforce`` causes IMA to appraise files . Access is denied to the
  appraised file if the stored hash is missing or does not match the
  collected value.

* ``log`` is similar to ``enforce`` except access is not denied but
  only logged to ``/var/log/audit/audit.log``.


* ``off`` disables all appraisal. The stored hashes aren't checked or
  logged.  New stored hashes are not generated or updated.


* ``fix`` enables the IMA repair mode. The stored hash reference value
  of a protected file can be created or updated. The file hash is
  (re)calculated and stored.

  ``fix`` is often used on first boot. This will allow the system to
  boot up even when no (or wrong) hashes are registered.

  ``fix`` only creates and updates hashes on files that would
  otherwise be appraised.  If using a custom IMA policy, that policy
  must be loaded first. If neither :ref:`ima-policy-appraise-tcb` nor
  a custom policy is loaded, the default policy is to not appraise
  anything, and ``fix`` will have no effect. Additionally, this
  process may need to be repeated if there's a change in the IMA
  policy.

  ``fix`` only updates hashes on files that have no signatures.  It
  cannot create a file signature.

A typical procedure for adding file data hashes and meta-data HMAC is:

* boot first in ``fix`` mode
* open for read all files that will be appraised

    Example

    ::

       find / -fstype ext4 -type f -uid 0 -exec dd if='{}' of=/dev/null count=0 status=none \;

* When done, the stored hash value should show as an extended attribute:

    Example

    ::

       getfattr -m - -d /sbin/init
       # file: sbin/init
       security.ima=0sAXr7Qmun5mkGDS286oZxCpdGEuKT
       security.selinux="system_u:object_r:init_exec_t"

* reboot in ``appraise`` mode

  The system should now run with appraisal enabled, causing the system
  to validate the hash against the stored value before using it. If it
  doesn't match, then the file is not loaded and any access will be
  denied.

Note: Appraisal can be verified by booting with ima_appraise= ``off``
, changing the contents of a root-owned file (or the value of the
extended attribute), and rebooting with ima_appraise= ``enforce``.

.. _evm:

evm
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``evm`` argument can take one value, ``evm=fix``.  It requires
:ref:`ima-appraise` ``=fix``.

It has the same effect as :ref:`ima-appraise` ``=fix``, but updates the
:ref:`evm-hmac`.


.. _template-specifiers:

Template Specifiers
-----------------------------------

.. _ima-template:

ima_template
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``ima_template=`` argument specifies boot time :ref:`ima-event-log`
:ref:`built-in-templates`.  There are several 
:ref:`built-in-templates`. See :ref:`built-in-templates` for their
effect.

Custom templates described in :ref:`template-data-fields` are not
supported.  Some may work, but their use is deprecated.  Use
:ref:`ima-template-fmt` to specify custom templates.


The default value is compiled in as CONFIG_IMA_DEFAULT_TEMPLATE_. The
supported values for ``ima_template=`` are:

* :ref:`ima`
* :ref:`ima-ng`
* :ref:`ima-sig`
* :ref:`ima-buf`
* :ref:`ima-modsig`
* :ref:`ima-ngv2`
* :ref:`ima-sigv2`
* (:ref:`evm-sig`) - While this is currently allowed, it is not
  recommended because it would apply to items that are not files with
  EVM signature attributes.

.. _ima-canonical-fmt:

ima_canonical_fmt  
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``ima_canonical_fmt`` option sets the canonical format for the binary runtime
measurements, instead of host native format.

It forces the event log to store all integral values as little endian
on big endian machines.

**Recommendation:**

This option is suggested on all big endian machines, since a verifier
may not be written to handle big endian event logs.

It is strongly suggested on a big endian machine that may receive a
kexec(), since the event log may otherwise be a mix of big and little
endian measurements.

.. warning::

   **FIXME Test this**

.. _ima-template-fmt:

ima_template_fmt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As an alternative to the built-in templates, a custom template can be
specified using the fields from :ref:`template-data-fields`,
concatenated using the ``|`` character.

Use :ref:`ima-template` to specify the :ref:`built-in-templates`.

