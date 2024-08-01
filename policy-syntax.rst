.. _policy-syntax:

===================================
Policy Syntax
===================================

Each line defines a policy rule. A policy rule contains these fields:

* `Policy Syntax Action`_
* `Policy Syntax Conditions`_

A rule must have an action. A rule must have at least one condition
and may have more than one.

The policy is parsed until the first match for each of the three
statement types: measure, appraise, and audit. Typically, “dont\_”
statements will come before “do” statements.

.. _policy-syntax-action:

Policy Syntax Action
===================================

An Action is often followed by :ref:`policy-syntax-conditions`.
Without conditions, the rule matches anything.  Such a rule typically
follows a set of "dont\_" rules.

The meta-data has either a hash or a signature.

-  ``measure`` - add a measurement to the IMA event log and the TPM PCR
-  ``dont_measure`` - do not measure the event
-  ``appraise`` - evaluate a file’s integrity. A file’s integrity may be a
   file hash or signature.  Appraisal requires a :ref:`func` condition.
-  ``dont_appraise`` - do not appraise the event
-  ``audit`` - include the file hash into the audit log. There is no
   dont_audit.
-  ``hash`` - when verifying file data, update the file data hash. This
   action permits the appraise built-in policy to verify on the next
   reboot
- ``dont_hash`` - opposite of hash

   The use case for ``hash`` is as follows:

   There can be one set of policy rules at boot, another custom policy
   when running. Suppose that the custom policy does not appraise certain
   files, but the boot time policy (being generic) would appraise them.
   When such a file is created, it would fail appraisal at a reboot.

   To avoid appraisal failure of a newly created file by the boot
   policy, install a ``hash`` rule (in the custom policy) to have a
   hash created for the file. At the reboot, the hash is correct and
   the boot time ``appraise`` policy rule does not cause a failure.

A measurement never blocks access to a file.

An appraisal failure may block the operation specified by the
:ref:`func` condition.  The action depends on several factors:

- If the kernel parameter :ref:`config-ima-appraise-bootparam` is
  false, IMA must be in ``enforce`` mode. The operation is blocked.

- If the kernel parameter :ref:`config-ima-appraise-bootparam` is
  true, there are four different boot modes. They can be specified in the
  :ref:`boot-command-line-arguments` :ref:`ima-appraise`.

   - :ref:`ima-appraise` = ``enforce`` - The operation is blocked.
   - :ref:`ima-appraise` = ``off`` - The operation is not blocked.
   - :ref:`ima-appraise` = ``log`` - Log the failure to the system log.
     The operation is not blocked.
   - :ref:`ima-appraise` = ``fix`` - Update the file hash and label
     it.  See :ref:`evm` = ``fix`` for updating the :ref:`evm-hmac`. An
     asymmetric (e.g., RSA, ECDSA) signature cannot be updated.

.. _policy-syntax-conditions:

Policy Syntax Conditions
===================================

These conditions qualify the :ref:`policy-syntax-action`. Each action
must have at least one condition.  If a policy rule has multiple
conditions then all of these conditions have to be met for the action
to be triggered (logical AND).

File policy rules may include the filesystem, owner, etc.,
but not the path name.  The file can be anywhere or have links.  The
measurement logs may contain the file path, but that is a hint.  The
file data hash is what uniquely identifies the file.

.. _func:

func
-----------------------------------

Some ``func`` values are only valid for certain Actions, and some
``measure`` values force an IMA template.

================================= ============== ======== ===== ====
func                              measure        appraise audit hash
--------------------------------- -------------- -------- ----- ----
:ref:`func-mmap-check`		  yes	         yes	  yes   yes
:ref:`func-bprm-check`		  yes	         yes	  yes   yes
:ref:`func-creds-check`		  yes            yes      yes   yes
:ref:`func-file-check`		  yes	         yes	  yes   yes
:ref:`func-module-check`	  yes	         yes	  yes   yes
:ref:`func-firmware-check`	  yes	         yes	  yes   yes
:ref:`func-policy-check`	  yes	         yes	  yes   yes
:ref:`func-kexec-kernel-check`	  yes	         yes	  yes   yes
:ref:`func-kexec-initramfs-check` yes            yes      yes
:ref:`func-kexec-cmdline`	  :ref:`ima-buf`
:ref:`func-key-check`	          :ref:`ima-buf`
:ref:`func-critical-data`	  :ref:`ima-buf`
:ref:`func-setxattr-check`                       yes
================================= ============== ======== ===== ====

``KEXEC_KERNEL_CHECK``, ``KEXEC_INITRAMFS_CHECK``, and
``KEXEC_CMDLINE`` apply to a soft reboot (a kexec() system call), not
the original hard boot.  The hard boot items should be measured by
the firmware.

.. _func-mmap-check:

func=MMAP_CHECK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This triggers when a file, such as a library, is mmapped into
memory.

This can be used for the case where a file is open for read (not
execute) and later mmapped for execute.

.. _func-bprm-check:

func=BPRM_CHECK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Binary program check triggers when a file is about to be executed. It
uses the existing (parent) process credentials. See also
:ref:`func-creds-check`, which triggers using the child process
credentials.

   The ``BPRM_CHECK`` rule triggers as close as possible to file
   execution, when the file can no longer be modified.
   With a :ref:`func-file-check` :ref:`mask` =MAY_EXEC rule, it is
   possible for the file to be modified by an open for write after the
   rule triggers but before the actual execution.

Example: If user 48 is the apache user id, this policy rule
triggers when a file is executed by the apache httpd daemon.

::

      measure func=BPRM_CHECK mask=MAY_EXEC uid=48

Example: This policy rule triggers when a file owned by root is
executed.

::

      appraise func=BPRM_CHECK mask=MAY_EXEC fowner=0

Example: This policy rule measures all executables, but not
configuration files.

::

	measure func=BPRM_CHECK mask=MAY_EXEC

Example: This policy rule triggers if the process that calls exec() is
already executing in unconfined_t, ignoring the context that the child
process executes into.

::

      measure func=BPRM_CHECK subj_type=unconfined_t

.. _func-creds-check:

func=CREDS_CHECK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``CREDS_CHECK`` triggers when a file is about to be executed. It uses
the new child process credentials, ignoring the parent process.  E.g.,
a suid process will gain privileges.

See also :ref:`func-bprm-check`, which triggers using the parent
process credentials.

Credentials include the process user and group (object), effective
user and group (subject), suid and sgid.

Example: This policy rule triggers if a process is executed and
runs as unconfined_t, ignoring the context of the parent process.

::

   measure func=CREDS_CHECK subj_type=unconfined_t


.. _func-file-check:

func=FILE_CHECK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This triggers on a file open, see :ref:`mask`.

This rule is not recommended with :ref:`mask` =MAY_EXEC.  Use
:ref:`func-bprm-check`.

::

    measure func=FILE_CHECK mask=MAY_READ uid=0
    appraise func=FILE_CHECK mask=^MAY_READ

.. _func-module-check:

func=MODULE_CHECK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This triggers on loading a kernel module (e.g., a device driver, a .ko
file).

Note:

IMA only measures and appraises kernel modules loaded by the
finit_module() syscall. IMA does not measure or appraise kernel
modules loaded by the init_module() syscall.

if ``CONFIG_MODULE_SIG`` is enabled, then the init_module() syscall is
used. An application can avoid the func=MODULE_CHECK measurement by
calling init_module() specifying a memory buffer rather than a disk
file. In this case, func=MODULE_CHECK is ineffective.

This policy is better, but can still be bypassed.

::

   measure func=FILE_CHECK mask=MAY_READ uid=0


If ``CONFIG_MODULE_SIG`` is disabled (the better choice),
finit_module() is used and measurements will occur.

The system does its own signature checking independent of IMA if
``CONFIG_MODULE_SIG`` is enabled and either
``CONFIG_MODULE_SIG_FORCE`` is enabled or the boot command line
contains ``module.sig_enforce``.

For :ref:`ima-modsig`:

   If there is a ``measure`` rule but no ``appraise`` rule, the
   measurement will be added to the event log without the appended
   signature.

   If both ``measure`` and ``appraise`` rules trigger for a compressed
   kernel module, the appraisal **will fail**.  If they trigger for an
   uncompressed kernel module, the measurement will be added to the event
   log with the appended signature. The order of the ``measure`` and
   ``appraise`` rules does not matter.

   Example: This policy triggers for kernel modules. **Do not use this
   appraise rule on compressed kernel modules.**

::

   measure func=MODULE_CHECK template=ima-modsig
   appraise func=MODULE_CHECK appraise_type=imasig|modsig


.. _func-path-check:

func=PATH_CHECK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Obsolete. Do not use. Use :ref:`func-file-check`.

.. _func-firmware-check:

func=FIRMWARE_CHECK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This triggers on loading a file as a firmware blob into the
kernel. An example of firmware is peripheral firmware loaded at run
time.

::

   appraise func=FIRMWARE_CHECK appraise_type=imasig
   measure func=FIRMWARE_CHECK

.. _func-policy-check:

func=POLICY_CHECK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This triggers on loading a file as an additional IMA
:ref:`custom-policy`.

If this rule was not already present at the time that a policy is
loaded, it will trigger on future custom policy loads, but not the one
being loaded.

Since a custom policy replaces the :ref:`built-in-policy-rules`, the
custom policy should also have ``func=POLICY_CHECK`` to complete the
chain of trust.

This ``appraise`` rule asserts that the policy replacing the built-in
policy, either at boot time using ``/etc/ima/ima-policy`` or at
runtime by copying to ``/sys/kernel/security/ima/policy``, must be
validly signed. The signature over the file is verified (appraised)
using a key on the :ref:`dot-ima` keyring. If correct, the file
contents are copied.

::

   appraise func=POLICY_CHECK appraise_type=imasig

See :ref:`runtime-custom-policy` for guidance on handling a signed
policy.

.. _func-kexec-kernel-check:

func=KEXEC_KERNEL_CHECK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This triggers on loading a kernel image using kexec.

For :ref:`ima-modsig`:

   If there is a ``measure`` rule but no ``appraise`` rule, the
   measurement will be added to the event log without the appended
   signature.

See :ref:`sign-file-appended-signature`.

Example:

::

    measure func=KEXEC_KERNEL_CHECK template=ima-modsig
    appraise func=KEXEC_KERNEL_CHECK appraise_type=imasig|modsig


.. _func-kexec-initramfs-check:

func=KEXEC_INITRAMFS_CHECK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This triggers on loading the file as an initramfs in the kexec() system
call.

If there is a ``measure`` rule but no ``appraise`` rule, the
measurement will be added to the event log without the appended
signature.

The ``appraise`` rule will not (currently) work because the initramfs
is built on the target machine. It cannot be signed by the distro.
It would have to be signed by the target (which does not have the
private key).

Example:

::

   measure func=KEXEC_INITRAMFS_CHECK template=ima-modsig


.. _func-kexec-cmdline:

func=KEXEC_CMDLINE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This triggers on loading the kexec boot command line in the kexec() system
call.

It does not trigger on the hard boot command line.  That should be
measured by firmware.

``KEXEC_CMDLINE`` forces the IMA template to :ref:`ima-buf`
independent of the default or boot command line specifier.

::

   measure func=KEXEC_CMDLINE template=ima-buf


.. _func-key-check:

func=KEY_CHECK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This triggers when keys are added onto a key ring. See `keyrings`_ for
examples.

Example: This triggers when the root user adds a key to the
:ref:`dot-ima` keyring.

::

   measure func=KEY_CHECK uid=0 keyrings=.ima

``KEY_CHECK`` forces the IMA template to :ref:`ima-buf` independent of
the default or boot command line specifier.

.. _func-critical-data:

func=CRITICAL_DATA
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This triggers on a change to security critical data stored in kernel
memory such as an SELinux policy or state, device-mapper targets like
dm-crypt and dm-verity state, or the kernel version.

``CRITICAL_DATA`` forces the IMA template to :ref:`ima-buf`
independent of the default or boot command line specifier.
The measurement log data is described in buf :ref:`buf-critical-data`.

::

   measure func=CRITICAL_DATA
   measure func=CRITICAL_DATA label=selinux


.. _func-setxattr-check:

func=SETXATTR_CHECK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This triggers on a call to :ref:`setfattr` to set the ``security.ima``
file signature extended attribute.  The required :ref:`appraise-algos`
qualifier lists the approved algorithms.  It is only valid for an
``appraise`` action.

This rule permits a restriction on the :ref:`sig`
:ref:`signature-hash-algorithm` that can be set on the
``security.ima`` attribute. Any algorithm built into the kernel is
accepted.

The rule does not block writing an appended signature.

This example filters the :ref:`setfattr` parameters to permit those
hash algorithms. The approved algorithm list is in the policy rule.

::

   appraise func=SETXATTR_CHECK appraise_algos=sha256,sha384,sha512

.. _mask:

mask
-----------------------------------

mask qualifies and is only legal with :ref:`func-file-check`. Without
``mask``, the rule triggers on any of read, write, execute, or append.

The values match the kernel flags:

-  mask=MAY_READ - open for read
-  mask=MAY_WRITE - open for write
-  mask=MAY_EXEC - open for execute
-  mask=MAY_APPEND - open for append
-  mask=MAY_ACCESS - not supported, error
-  mask=MAY_OPEN - not supported, error
-  mask=MAY_CHDIR - not supported, error

If the flag is preceded by a ^, it matches if the access contains the
flag. For example, MAY_READ only matches a read, while ^MAY_READ
matches read or read/write.

.. _`keyrings-condition`:

keyrings
-----------------------------------

See :ref:`keyrings` for a description of the keyrings.

keyrings qualifies and is only legal with :ref:`func-key-check`.

Without keyrings, :ref:`func-key-check` measures all keyrings. With
``keyrings=``, it only measures the keyrings that are listed.

The commonly used keyrings are:

-  ``.blacklist``
-  ``.ima``
-  ``.builtin_trusted_keys``
-  ``.secondary_trusted_keys``
-  ``.machine``
-  ``.platform``
-  ``.builtin_regdb_keys``
-  ``.evm``

Example::

  measure func=KEY_CHECK keyrings=.ima|.builtin_trusted_keys

The \| is an OR list.


.. _fsmagic:

fsmagic
-----------------------------------

Hex value, prefix with 0x. A reference for the values is this `kernel
header
<https://github.com/torvalds/linux/blob/master/include/uapi/linux/magic.h>`_.
When the magic numbers are not available, see fsname_.

For the include actions (i.e., not the dont\_ actions), fsmagic
qualifies and is only legal with :ref:`func-file-check`.

IMA looks at the magic values of the filesystem itself, not those of the
individual files. The magic number indicates the filesystem type.

The most common use case for fsmagic is with ``dont_measure``, to
exclude files residing on a particular filesystem from being
measured. For example, a built-in policy excludes tmpfs, which holds
/tmp. Temporary files typically cannot be included on an approved list
of file hashes.

The command ``df -Th`` displays the file types present on a system.



Examples:

::

   dont_measure fsmagic=0x9fa0

blocks measurement of the /proc filesystem.
::

   measure fsmagic=0xEF53

triggers on ext4 filesystems.


fsname
-----------------------------------

``fsname`` can be used instead of fsmagic_ on filesystems such as XFS, where
the magic numbers are private and not exposed.

The string is based on the superblock's file_system_type name.

======================= ========================
fsname                  Description
----------------------- ------------------------
rootfs			FIXME
fuse			FIXME
xfs			FIXME
======================= ========================

.. warning::

   This needs a list of valid strings and definitions.

Examples:

::

   measure func=FILE_CHECK fsname=xfs
   appraise func=BPRM_CHECK fsname=rootfs appraise_type=imasig
   appraise func=FILE_MMAP fsname=rootfs appraise_type=imasig
   measure func=FILE_CHECK fsname=fuse


fsuuid
-----------------------------------

fsuuid represents the filesystem (partition) uuid.

This uuid is not standard across platforms. It is typically a random
number.  The uuid can be viewed using ``blkid`` as root.

A useful application of fsuuid is to define different rules for
different filesystems. This permits testing without bricking a
system.  For example, the signed operating system and stable
components can be put on a read-only file system and appraised, while
unsigned files being tested are on another, not appraised file system.

Examples of the syntax is

::

   measure func=BPRM_CHECK mask=MAY_EXEC  fsuuid=0b9afd9-c8ae-4bfc-84d2-f8d49f4b68f1
   measure func=FILE_CHECK fsuuid=b0b196af-9032-4b67-9e18-3689f9f19fd6 template=evm-sig

.. warning::

   **FIXME Can one specify the uuid? Try tune2fs -U to set
   uui. experiment - create a filesystem using gprtd, try changing uuid
   without unmount.**

uid=id
-----------------------------------

Filter by the calling process user id. id is a decimal value. The
``=``, ``<``, and ``>`` operators are supported.


euid=id
-----------------------------------

Filter by the calling process effective user id. id is a decimal
value. The ``=``, ``<``, and ``>`` operators are supported.

gid=id
-----------------------------------

Filter by the calling process group id. id is a decimal value. The
``=``, ``<``, and ``>`` operators are supported.

egid=id
-----------------------------------

Filter by the calling process effective group id. id is a decimal
value. The ``=``, ``<``, and ``>`` operators are supported.

fowner=id
-----------------------------------

Filter by the file owner id. id is a decimal value. The ``=``, ``<``,
and ``>`` operators are supported.

Different from uid, this can match a file independent of who is
executing it. If could be used to detect an attack in a system library
when a non-root user executes it.

fgroup=id
-----------------------------------

Filter by the file group id. id is a decimal value.  The ``=``, ``<``, and
``>`` operators are supported.

E.g., a policy rule could specify a file in the wheel group.

label
-----------------------------------

label qualifies and is only legal with :ref:`func-critical-data`.

Values include:

* ``selinux`` - measure SELinux state and policy.

Example::

  measure func=CRITICAL_DATA label=selinux

.. _appraise-type:

appraise_type
-----------------------------------

When present, this condition specifies that a ``security.ima`` hash is
not permitted and which signature formats are permitted.  See
:ref:`signature`.

The allowed values are:

* ``imasig``

  Require a signature in the ``security.ima`` extended attribute.

* ``imasig|modsig``

  Require a signature in the ``security.ima`` extended attribute or an
  ``appended signature``

* ``sigv3``

  Require v3 format signature in the ``security.ima`` extended
  attribute. This is limited to ``fsverity`` enabled files.

``modsig`` requires :ref:`config-ima-appraise-modsig`.

This example appraises an executable fs-verity file, and requires a
``sigv3``.

::

    appraise func=BPRM_CHECK digest_type=verity appraise_type=sigv3

This example measures and appraises a kexec kernel image with an
appended signature or a signature in a ``security.ima`` extended
attribute..

::

    measure func=KEXEC_KERNEL_CHECK template=ima-modsig
    appraise func=KEXEC_KERNEL_CHECK appraise_type=imasig|modsig


.. _template:

template
-----------------------------------

This condition overrides the format of the :ref:`ima-event-log` /
:ref:`template-data` for the rule that is triggered.  **It is
only valid for** ``measure``.

``template`` is a string.  Note that ``ima_template`` is used on the
boot command line, but ``template`` is used in a policy rule.

The string can be one of the :ref:`built-in-templates`.

The string can be a custom template in the format described in
:ref:`template-data-fields`. However, only those that match one
of the :ref:`built-in-templates` are legal, and the result is mapped to
one of the :ref:`built-in-templates`.  Other custom templates are
rejected.

Example: These are legal and equivalent.

::

   measure func=FILE_CHECK mask=MAY_READ fowner=1001 template=ima-ng
   measure func=FILE_CHECK mask=MAY_READ fowner=1001 template=d-ng|n-ng

For an attestation server to validate an EVM signature, use the
:ref:`evm-sig` template.

::

   measure func=FILE_CHECK fsuuid=b0b196af-9032-4b67-9e18-3689f9f19fd6 template=evm-sig


permit_directio
-----------------------------------

This condition has no parameters. If the file is opened with the
``O_DIRECT`` flag, this rule prevents the file from being measured or
appraised.

Direct I/O (open with the ``O_DIRECT`` flag) is used to bypass
filesystem buffering. The open permits direct access to the file
without buffering.  It is often used for databases.

Without ``permit_directio``, IMA would read the entire file, thus thus
defeating the expected performance gain expected from direct I/O. The
following rules show how to prevent this:

   ::

	measure func=FILE_CHECK  obj_type=mysql_db_t permit_directio
	appraise func=FILE_CHECK  obj_type=mysql_db_t permit_directio


.. warning::

   Example needs testing.

.. _digest-type:

digest_type
-----------------------------------

This condition requires a file to have an fs-verity file digest
rather than the regular IMA file hash.

The permitted value is:

* ``digest_type=verity``

If the file fs-verity digest is present (i.e., it is an fsverity
enabled file), the IMA event log records the fs-verity digest - a hash
of the root of the Merkle tree plus meta-data.

If the fs-verity digest is not present, the event log records an all
zeros digest, indicating an error.

``digest_type=verity`` requires the IMA template to be either
:ref:`ima-ngv2` or :ref:`ima-sigv2`.

These example ``measure`` policy rules requires fs-verity digests.

::

    measure func=FILE_CHECK digest_type=verity template=ima-ngv2
    measure func=BPRM_CHECK fsuuid=14952e4e-4d48-43b1-afba-2d9b84f860ef template=ima-sigv2 digest_type=verity

See :ref:`config-fs-verity`.

.. _appraise-flag:

appraise_flag
-----------------------------------

``appraise_flag`` affects only :ref:`appraisal` of a file with an
appended :ref:`signature`.

As of kernel 6.6 (plus backports), this flag is superfluous, as the
feature is always enabled. A :ref:`hash` or a :ref:`signature` is
checked against the :ref:`dot-blacklist` for all files.

The pre-6.6 optimization is described below.

The permitted value is:

*  ``appraise_flag=check_blacklist``

If present, this rule qualifier ensures that the file data :ref:`hash`
is not on the :ref:`dot-blacklist` keyring.

If not present, the file data :ref:`hash` is not validated against the
:ref:`dot-blacklist` keyring.

This rule does not affect :ref:`signature` verification.  The
:ref:`dot-blacklist` is always checked for invalid public keys.

This rule permits the :ref:`dot-blacklist` to have finer resolution
than blacklisting a verification public key. The intent is that the
:ref:`dot-blacklist` will be limited to the kexec kernel image and
kernel modules. Therefore, other items would never be on the
:ref:`dot-blacklist`, and checking it would incur an unnecessary
performance penalty.

These examples show that the :ref:`dot-blacklist` keyring is only
checked for a file data :ref:`hash` in the two above cases.

::

   appraise func=KEXEC_KERNEL_CHECK appraise_flag=check_blacklist appraise_type=imasig|modsig
   appraise func=MODULE_CHECK appraise_flag=check_blacklist appraise_type=imasig|modsig

.. _appraise-algos:

appraise_algos
-----------------------------------

``appraise_algos`` provides the approved signature hash algorithm list
to the :ref:`func-setxattr-check` policy rule.

The value is a comma separated list of hash algorithms, and can
include any hash algorithm built into the kernel.

In this example, only SHA-256 and SHA-384 are accepted when adding a
``security.ima`` file signature extended attribute.

::

      appraise func=SETXATTR_CHECK appraise_algos=sha256,sha384

.. _pcr-value:

pcr=value
-----------------------------------

value is a positive decimal number.

This overrides :ref:`config-ima-measure-pcr-idx`.

The use case for a ``pcr=`` rule is a Linux-based (not UEFI) boot
loader. Here, IMA in the boot loader is measuring and extending PCRs
other than PCR 10.

This example shows the firmware to operating system transition (kexec)
measured into PCR 4 and the initramfs measured into PCR 5.

::

      measure func=KEXEC_KERNEL_CHECK pcr=4
      measure func=KEXEC_INITRAMFS_CHECK pcr=5

Note:

   There is no guaranteed range check on the PCR value.  Kernel
   6.2.14-200 accepts PCR 0-63.  A typical TPM supports PCR 0-23 but
   some are restricted based on locality.


.. _obj-user-equals:

obj_user=
-----------------------------------

This string is an LSM label.

:ref:`config-ima-lsm-rules` enables this rule.

.. warning::

   The legal values are:

   Example::

      Needs examples.

.. _obj-role-equals:

obj_role=
-----------------------------------


The string is an LSM label.

:ref:`config-ima-lsm-rules` enables this rule.

.. warning::

   The legal values are:

   Example::

      Needs examples.

.. _obj-type-equals:

obj_type=
-----------------------------------

The string is an LSM label. See :ref:`obj-type` for examples.

:ref:`config-ima-lsm-rules` enables this rule.

These examples exclude log files and database tables, which will not
have approved hash values.

::

	dont_measure obj_type=var_log_t
	dont_measure obj_type=mysql_db_t

.. _subj-user-equals:

subj_user=
-----------------------------------

This string is an LSM SELinux label.

:ref:`config-ima-lsm-rules` enables this rule.

Example:

::

	measure func=BPRM_CHECK subj_type=unconfined_t
	measure func=FILE_CHECK mask=MAY_READ subj_user=system_u 

.. _subj-role-equals:

subj_role=
-----------------------------------

This string is an LSM SELinux label.

:ref:`config-ima-lsm-rules` enables this rule.

Example:

::

	measure func=FILE_CHECK mask=MAY_READ subj_role=system_r


.. _subj-type-equals:

subj_type=
-----------------------------------

This string is an LSM SELinux label.

:ref:`config-ima-lsm-rules` enables this rule.

.. warning::

      Needs examples.

SELinux variations
-----------------------------------

Builtin policy rules may measure too much. Measurement and appraisal
of log files are not useful, generating events every time one is
opened. Known log files can be excluded using SELinux to constrain
which files are measured.

See :ref:`selinux-labels`.

SMACK
-----------------------------------

.. warning::

   **FIXME Needs documentation**

