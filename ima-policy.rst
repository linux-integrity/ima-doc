IMA Policy
----------

.. _measure-policy-rule-design:

Measure Policy Rule Design
~~~~~~~~~~~~~~~~~~~~~~~~~~~

While a good design should measure all security relevant events, there
are good reasons to not simply "measure everything".

As described below, only stable, mostly read-only, well
known items should be measured.  Examples are binaries, shared
libraries, and system configuration files. Frequently changing items
should not be measured.  Examples are log files or databases.

1. **Performance**.  The TPM is slow. This not an issue for an item
that rarely changes, since IMA tracks measurements and does not
re-measure an item that has not changed.  However, items that change
often will cause frequent measurements, degrading performance.

2. **Event log size**: Each log record can be 100 bytes. A system
might have 5000 records at boot and grow as large as 100,000 records
over time. This is reasonable unless the platform is memory
constrained.

Beware that, if an installation expects a ``kexec``, and assuming that
the event log is carried across the kexec, the size will grow roughly
linearly with the number of kexec's.

See :ref:`kexec-ima-impact`.

However, if a measured item changes often, there is no longer any
typical log size.  Each change can cause a new measurement and 1M's of
measurements are possible.

3. **Verifier performance**: The verifier uses a TPM ``quote`` as an
integrity signature over the IMA event log. It needs all events to
verify the log.

A verifier typically caches results and does an incremental
attestation.  Only events since the last quote need be sent and
processed. Once most events have been processed, the size of the event
log is immaterial.

However, policy rules that cause continuous new measurements will
require those measurements to be sent to the verifier and processed.
This increases the network and verifier load, important as the
verifier scales to support many attesters.

4. **Security assertions**: The end goal of measurements and
attestation is to permit the verifier to assess the security state of
the attester.  The verifier does this by comparing the event log
hashes to approved lists.  For example, the verifier might have a list
of file hashes for executables and shared libraries.

However, items that change often will not have approved hashes.
Hashes cannot be reversed to calculate the item.  Therefore, the
verifier cannot assess its security properties.

.. _appraise-policy-rule-design:

Appraise Policy Rule Design
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Appraisal rules are restricted based on ``func`` values as shown in
the :ref:`func` table.

The kernel configuration (see :ref:`appraise`) and the boot command
line (see :ref:`boot-command-line-arguments` and
:ref:`ima-appraise-policies`) determine the ``appraise`` policy rules.
The typical initial setting :ref:`ima-policy-appraise-tcb` appraises
all files owned by root.

IMA can prevent a signed file from being altered online if it is
included in the ``FILE_CHECK`` rule for write.

Rules should not appraise pseudo-filesystems (e.g., debugfs,
securityfs, or selinuxfs). They are not real files and do not support
extended attributes. Add ``dont_appraise`` rules for these
pseudo-filesystems.  See :ref:`ima-policy-appraise-tcb` for an
example.

This example appraisal policy excludes several pseudo-filesystems.

::

   # PROC_SUPER_MAGIC
   dont_appraise fsmagic=0x9fa0
   # SYSFS_MAGIC
   dont_appraise fsmagic=0x62656572
   # DEBUGFS_MAGIC
   dont_appraise fsmagic=0x64626720
   # RAMFS_MAGIC
   dont_appraise fsmagic=0x858458f6
   # DEVPTS_SUPER_MAGIC
   dont_appraise fsmagic=0x1cd1
   # BINFMTFS_MAGIC
   dont_appraise fsmagic=0x42494e4d
   # SECURITYFS_MAGIC
   dont_appraise fsmagic=0x73636673
   # SELINUXFS_MAGIC
   dont_appraise fsmagic=0xf97cff8c
   # SMACK_MAGIC
   dont_appraise fsmagic=0x43415d53
   # NSFS_MAGIC
   dont_appraise fsmagic=0x6e736673
   # CGROUP_SUPER_MAGIC
   dont_appraise fsmagic=0x27e0eb
   # CGROUP2_SUPER_MAGIC
   dont_appraise fsmagic=0x63677270

Rules would not appraise log files, cache files, and other rapidly
changing files lacking a known trusted value.

One test configuration may be to appraise one filesystem, where all
files are signed, while not appraising another file system which
contains unsigned files being tested.

IMA does not prevent a file from being altered offline. An altered
file will (depending on policy rules) not be readable or executable.
E.g., :ref:`appraise-type` can require a signature.


.. _policy-rule-order:

Policy Rule Order
~~~~~~~~~~~~~~~~~~~

Policy rules can originate from several sources.  They are determined in this order

#. :ref:`built-in-policy-rules` for measurement.  See :ref:`ima-policy-tcb`
#. Architecture specific policy rules from :ref:`build-flags` such as :ref:`config-ima-arch-policy`.
#. :ref:`built-in-policy-rules` for secure boot appraisal.  See :ref:`ima-policy-secure-boot`.
#. Build time policy rules from :ref:`build-flags` for finer control than :ref:`ima-policy-secure-boot`.

   a. :ref:`config-ima-appraise-require-module-sigs`.
   b. :ref:`config-ima-appraise-require-firmware-sigs`.
   c. :ref:`config-ima-appraise-require-kexec-sigs`.
   d. :ref:`config-ima-appraise-require-policy-sigs`.
#. Build time :ref:`built-in-policy-rules` for appraisal.  See :ref:`ima-policy-appraise-tcb`.
#. Build time :ref:`built-in-policy-rules` for measure.  See :ref:`ima-policy-critical-data`.

After a :ref:`custom-policy` is loaded, the order becomes:

#. Architecture specific :ref:`build-flags` such as :ref:`config-ima-arch-policy`.
#. Build time :ref:`build-flags` for finer control.

   a. :ref:`config-ima-appraise-require-module-sigs`.
   b. :ref:`config-ima-appraise-require-firmware-sigs`.
   c. :ref:`config-ima-appraise-require-kexec-sigs`.
   d. :ref:`config-ima-appraise-require-policy-sigs`.

#.  :ref:`custom-policy`.

:ref:`ima-policy` can be specified multiple times, and the result is
the concatenation of the policies in a hard coded order listed in
:ref:`ima-policy`.

.. _reading-policies:

Reading Policies
~~~~~~~~~~~~~~~~~~~

The policy rules currently in effect can be viewed in the pseudo-file
``/sys/kernel/security/ima/policy``.

The policy can be read if :ref:`config-ima-read-policy` is true when building
the kernel.

.. _built-in-policy-rules:

Built-in Policy Rules
~~~~~~~~~~~~~~~~~~~~~~

Built-in policy rules are compiled into the kernel. Their contents cannot
be changed, but they can be replaced at boot time or run time.  They
are specified using the :ref:`boot-command-line-arguments`.

The boot command selects the built-in policy. The command can be
specified on the boot command line (single boot) or in the grub
configuration file (persistent).

The pseudofile ``/proc/cmdline`` will display the boot command line.
``grubby --info=ALL`` displays all the boot command choices.

Enabling secure boot in the firmware adds these policy statements:

::

   measure func=KEXEC_KERNEL_CHECK
   measure func=MODULE_CHECK

The policy rules added by secure boot in the firmware are not
replaced.

The secure boot state can be tested with

::

   mokutil --sb state

Specifying none of the below on the command line yields a policy
with no policy rules.

.. _ima-measurement-policies:

IMA Measurement Policies
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Refer to :ref:`fsmagic` for the value meanings. See :ref:`policy-rule-order`.

ima_tcb
'''''''''''''''

  Deprecated, see :ref:`ima-policy-tcb`.

  ::

   dont_measure fsmagic=0x9fa0		PROC_SUPER_MAGIC
   dont_measure fsmagic=0x62656572	SYSFS_MAGIC
   dont_measure fsmagic=0x64626720	DEBUGFS_MAGIC
   dont_measure fsmagic=0x1021994	TMPFS_MAGIC
   dont_measure fsmagic=0x1cd1		DEVPTS_SUPER_MAGIC
   dont_measure fsmagic=0x42494e4d	BINFMTFS_MAGIC
   dont_measure fsmagic=0x73636673	SECURITYFS_MAGIC
   dont_measure fsmagic=0xf97cff8c	SELINUX_MAGIC
   dont_measure fsmagic=0x43415d53	SMACK_MAGIC
   dont_measure fsmagic=0x27e0eb	CGROUP_SUPER_MAGIC
   dont_measure fsmagic=0x63677270	CGROUP2_SUPER_MAGIC
   dont_measure fsmagic=0x6e736673	NSFS_MAGIC
   dont_measure fsmagic=0xde5e81e4	EFIVARFS_MAGIC
   measure func=MMAP_CHECK mask=MAY_EXEC
   measure func=BPRM_CHECK mask=MAY_EXEC
   measure func=FILE_CHECK mask=MAY_READ uid=0
   measure func=MODULE_CHECK
   measure func=FIRMWARE_CHECK


.. _ima-policy-tcb:

ima_policy=tcb
'''''''''''''''

  ``tcb`` applies an IMA policy that meets the needs of the Trusted Computing Base
  (TCB).

  The rules measure all programs directly executed or mmap'd for
  execution (such as shared libraries).  They measure files opened by
  root ((euid, uid) == 0) with the read bit set.  It measure all
  kernel modules loaded and all firmware loaded.

  The policy excludes some "pseduo" filesystem from measurement.

::

   dont_measure fsmagic=0x9fa0		PROC_SUPER_MAGIC
   dont_measure fsmagic=0x62656572	SYSFS_MAGIC
   dont_measure fsmagic=0x64626720	DEBUGFS_MAGIC
   dont_measure fsmagic=0x1021994	TMPFS_MAGIC
   dont_measure fsmagic=0x1cd1		DEVPTS_SUPER_MAGIC
   dont_measure fsmagic=0x42494e4d	BINFMTFS_MAGIC
   dont_measure fsmagic=0x73636673	SECURITYFS_MAGIC
   dont_measure fsmagic=0xf97cff8c	SELINUX_MAGIC
   dont_measure fsmagic=0x43415d53	SMACK_MAGIC
   dont_measure fsmagic=0x27e0eb	CGROUP_SUPER_MAGIC
   dont_measure fsmagic=0x63677270	CGROUP2_SUPER_MAGIC
   dont_measure fsmagic=0x6e736673	NSFS_MAGIC
   dont_measure fsmagic=0xde5e81e4	EFIVARFS_MAGIC
   measure func=MMAP_CHECK mask=MAY_EXEC
   measure func=BPRM_CHECK mask=MAY_EXEC           binary executed
   measure func=FILE_CHECK mask=^MAY_READ euid=0
   measure func=FILE_CHECK mask=^MAY_READ uid=0    root executed r/o or r/w
   measure func=MODULE_CHECK
   measure func=FIRMWARE_CHECK
   measure func=POLICY_CHECK

.. _ima-policy-critical-data:

ima_policy=critical_data
''''''''''''''''''''''''''''''

  ``critical_data`` applies a policy that contains this rule.

  ::

   measure func=CRITICAL_DATA

.. _ima-appraise-policies:

IMA Appraise Policies
^^^^^^^^^^^^^^^^^^^^^^^^^^^

See :ref:`policy-rule-order`.

.. _ima-policy-secure-boot:

ima_policy=secure_boot
''''''''''''''''''''''''''''''

  ``secure_boot`` appraises loaded kernel modules, firmware, the kexec
  kernel image and the IMA policy itself, based on a file signature.

::

   appraise func=MODULE_CHECK appraise_type=imasig
   appraise func=FIRMWARE_CHECK appraise_type=imasig
   appraise func=KEXEC_KERNEL_CHECK appraise_type=imasig
   appraise func=POLICY_CHECK appraise_type=imasig

.. _ima-appraise-tcb:

ima_appraise_tcb
''''''''''''''''''''''''''''''

  Deprecated, same as :ref:`ima-policy-appraise-tcb`.


.. _ima-policy-appraise-tcb:

ima_policy=appraise_tcb
''''''''''''''''''''''''''''''

  ``appraise_tcb`` appraises all files owned by root. The policy
  excludes some "pseduo" filesystem from appraisal.


  ::

   dont_appraise fsmagic=0x9fa0		PROC_SUPER_MAGIC
   dont_appraise fsmagic=0x62656572	SYSFS_MAGIC
   dont_appraise fsmagic=0x64626720	DEBUGFS_MAGIC
   dont_appraise fsmagic=0x1021994	TMPFS_MAGIC
   dont_appraise fsmagic=0x858458f6	RAMFS_MAGIC
   dont_appraise fsmagic=0x1cd1		DEVPTS_SUPER_MAGIC
   dont_appraise fsmagic=0x42494e4d	BINFMTFS_MAGIC
   dont_appraise fsmagic=0x73636673	SECURITYFS_MAGIC
   dont_appraise fsmagic=0xf97cff8c	SELINUX_MAGIC
   dont_appraise fsmagic=0x43415d53	SMACK_MAGIC
   dont_appraise fsmagic=0x6e736673	NSFS_MAGIC
   dont_appraise fsmagic=0x27e0eb	CGROUP_SUPER_MAGIC
   dont_appraise fsmagic=0x63677270	CGROUP2_SUPER_MAGIC
   appraise func=POLICY_CHECK appraise_type=imasig
   appraise fowner=0

If :ref:`config-ima-appraise-signed-init` is defined, the rule

   ::

    appraise fowner=0

is replaced by the rule

   ::

    appraise fowner=0 appraise_type=imasig

which requires all files to be signed.  Hash is insufficiant.

.. _ima-policy-fail-securely:

ima_policy=fail_securely
''''''''''''''''''''''''''''''

``file_securely`` affects the appriasal of untrusted mounted
filesystems. An example is a FUSE filesystem.

FUSE (Filesystem in Userapce) filesystems are inherently untrusted.  A
file's data content presented on file open is not necessarily the same
file data content subsequently accessed.  For this reason, files on
unprivileged mounted FUSE filesystems are never trusted; files on
privileged FUSE mounted filesystems are "trusted" unless the boot
command line policy is specified.

When present, appraisal of untrusted mounted filesystems always
fails.  An example is a Fuse filesystem mounted by root.

When absent, they do not fail.

An untrusted filesystem not mounted by root always fails appraisal.

IMA Template Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^

ima_template
''''''''''''''''''''''''''''''

This boot command line argument sets a logging format for the
:ref:`ima-event-log`.  See :ref:`config-ima-default-template` for the
compiled in default. See :ref:`built-in-templates` for legal values.
See the values in :ref:`template-data-fields` for the
effects.

ima_template_fmt
''''''''''''''''''''''''''''''

This boot command line argument sets a logging format for the
:ref:`ima-event-log`. See :ref:`template-data-fields`
for the custom template legal values.

   Note: The ``n`` field is deprecated.

.. warning::

   **FIXME This needs an example, like d|n. Are there quotes or
   brackets?**


.. _custom-policy:

Custom Policy
~~~~~~~~~~~~~

A custom policy may specified at boot time or at run time, or both.

The policy file has one :ref:`policy-syntax-action` per line.  Empty
lines are forbidden.  Lines beginning with ``#`` are comments.  Use

::

   dmesg

to check for errors. 

If running appraisal and

::

   appraise func=POLICY_CHECK

is part of the built-in policy, the custom policy file is itself
appraised. For example, the :ref:`boot-time-custom-policy`, typically
``/etc/ima/ima-policy`` has to itself be signed.


.. _boot-time-custom-policy:

Boot Time Custom Policy
^^^^^^^^^^^^^^^^^^^^^^^

The boot time policy, if specified in ``/etc/ima/ima-policy``, is
loaded during Linux initialization. That is, early in Linux boot, a
built-in policy is used. See :ref:`built-in-policy-rules`. At some
point, the file system becomes available and ``/etc/ima/ima-policy``
becomes the IMA policy, replacing the built-in policy.

The IMA policy pathname is configurable in dracut ``/etc/sysconfig/ima``.

If ``/etc/ima/ima-policy`` does not exist, IMA keeps using the
:ref:`built-in-policy-rules`.  policy. **Any malformed policy,
including an empty file (zero length) is illegal and will prevent
Linux from booting.**

**Test the custom policy first.** Put the policy in a temporary file,
then cp the file to ``/sys/kernel/security/ima/policy``. On failure,
use ``dmesg`` to check for errors.

.. warning::

  There is a corner case where the test does not work.

  On boot, all selinux labels must exist.  But during these test cp,
  they do not have to exist.

  Explain it and the recovery procedure.

.. _run-time-custom-policy:

Run Time Custom Policy
^^^^^^^^^^^^^^^^^^^^^^

A policy can be augmented at run time. A custom policy from a file can
be copied (cp can be used) to ``/sys/kernel/security/ima/policy``.

If a boot time custom policy was not specified, the first custom policy
replaces the existing policy.

If a boot time custom policy was specified, the first custom policy is
appended to the exist policy.

Subsequent updates, if permitted, are appends.

If the kernel is configured with :ref:`config-ima-write-policy` false,
the copy may be done once per boot. If true, the policy may be updated
multiple times.

A malformed policy will report the error ``cp: error writing 'policy':
Invalid argument`` and ``dmesg`` will display the error.

As an alternative, a fully qualified path name can be copied. A slash
(/) as the first character causes the contents to be treated as a file
name rather than a list of policy rules. The contents of that file is
the list of policy rules.

This alternative is required when appraisals require signed policies.
See :ref:`func-policy-check`.


.. warning::

   Test with signed policies. Do cat and cp both work?