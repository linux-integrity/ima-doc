.. toctree::
   :maxdepth: 8
   :caption: Event Log Format:

.. _ima-event-log:

===================================
IMA Event Log
===================================

The IMA-Measurement Event Log is also known as the IMA measurement
list. See :ref:`ima-and-evm-concepts`.

IMA Log Verification
===================================

IMA Attestation Background
-----------------------------------

An IMA attester and verifier design should note several differences
from verifying a pre-OS log. They occur because IMA-Measurement
records can occur during the attestation, when the measurement log and
quote are acquired.

-  An IMA event log append is not atomic with the TPM extend.

   Since a TPM quote can be requested at any time, it is possible that
   the IMA event log can have extra events. However, there will never
   be a missing event in the log since the log-append comes before the
   PCR extend.

   Further, an append-extend pair is atomic with other append-extend
   pairs, so the appends will never be out of order with the extends.

-  A TPM quote is not atomic with a TPM PCR read.

   A PCR read before or after a quote may not reflect the quoted PCR.

   This is different from TPM 1.2, where the quote command returned
   both the signature and the set of PCR values being quoted.  In TPM
   2.0, a quote and a PCR read are separate, not an atomic command.

-  IMA event logs are far larger than pre-OS logs.

   While a pre-OS log may hold 50 events, an IMA log can hold 10K –
   100K events.

IMA Attestation Recommendations
-----------------------------------

An implementation of an attester and verifier should consider the
following recommendations.

-  The verifier should account for extra events.

   Replay the event log until the quote matches and then discard extra
   events. Extra events are not a failure.

-  There is no advantage in reading the IMA PCR (PCR 10) and sending it
   to the verifier.

   Since the read is not atomic with the quote or the event log, a
   mismatch is not a failure.

   Looping through quote / PCR read cycles until the quote matches the PCR
   read will lead to poor performance and perhaps timeouts, especially
   early when IMA is measuring many files.

-  Design for incremental attestations.

   Until a reboot, the IMA event log receives only appends. Once the
   earlier measurements are verified, there is no need to verify them
   again. The verified PCR 10 value serves as state.

   For a long lived platform, eventually most files will be measured and
   few or no new events need be processed.

Template Recommendations
----------------------------

Template data usually includes the file name. While this cannot be
trusted, it provides a hint, a pointer to the approved file data hash.

There are two use cases that determine whether to include a signature:

- If there is no approved hash list, a signature can be verified. This
  proves that the file was signed correctly, but not whether the file
  itself is approved by the verifier.

- If there is an approved hash list, the file data hash can be
  verified. The verifier can approve specific files and/or versions.
  In this case, the file signature in the template data is
  superfluous.

There is a verifier performance benefit to comparing hashes over
checking signatures, but either check is normally only once per boot.

Multiple PCRs
-----------------------------------

IMA may extend to more than one PCR using the policy condition
:ref:`pcr-value`. Even in this case, the payload is added to the
**same** IMA event log.

Because there is only one IMA event log, and because each append /
extend operation is atomic with other pairs, the verification
algorithm does not change: replay the event log until the calculated
PCR digest matches that of the quote.

   Note: It is important that future IMA kernel designs do **not** use
   different event logs.  If that occurred, the verifier would replay
   multiple event logs, each of which could have extra events.
   Calculating the quoted PCR digest would become computationally
   difficult.


.. _ima-event-log-location:

IMA Event Log Location
===================================

The Linux kernel creates and writes the IMA Event Log (also known as
the measurement list or integrity log) pseudo-files.

There are two formats:

* The :ref:`ima-event-log-binary-format`
* The :ref:`ima-event-log-ascii-format`

The logs were originally at:

* ``/sys/kernel/security/ima/binary_runtime_measurements``
* ``/sys/kernel/security/ima/ascii_runtime_measurements``

In newer kernels, the logs are at:

* ``/sys/kernel/security/integrity/ima/binary_runtime_measurements``
* ``/sys/kernel/security/integrity/ima/ascii_runtime_measurements``

For backward compatibility

``/sys/kernel/security/ima``
is linked to
``/sys/kernel/security/integrity/ima``

A kernel between 6.10.6 and 6.10.11 added support for multiple hash
algorithms, with the logs corresponding to the **allocated** TPM PCR
banks.  The names append the hash algorithm string:

* ``/sys/kernel/security/integrity/ima/binary_runtime_measurements_sha1``
* ``/sys/kernel/security/integrity/ima/binary_runtime_measurements_sha256``
* ``/sys/kernel/security/integrity/ima/binary_runtime_measurements_sha384``
* ``/sys/kernel/security/integrity/ima/binary_runtime_measurements_sha512``
* ``/sys/kernel/security/integrity/ima/ascii_runtime_measurements_sha1``
* ``/sys/kernel/security/integrity/ima/ascii_runtime_measurements_sha256``
* ``/sys/kernel/security/integrity/ima/ascii_runtime_measurements_sha384``
* ``/sys/kernel/security/integrity/ima/ascii_runtime_measurements_sha512``

For backward compatibility

``binary_runtime_measurements`` and
``ascii_runtime_measurements``
are linked to 
``binary_runtime_measurements_sha1`` and
``ascii_runtime_measurements_sha1``

Normally, systemd mounts securityfs in the kernel. It is possible that
this pseudo-file will not exist because securityfs is not
mounted. Remedy this by adding this line to ``/etc/fstab``:

::

   none /sys/kernel/security securityfs defaults 0 0

I.e.,

* filesystem
  none
* mount point
  /sys/kernel/security
* type
  securityfs
* options
  defaults
* dump
  0
* pass
  0

``mount`` should show

::

	securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)

The first reader is typically an attestation application, which sends
the log along with a quote (a signature over the event log) to a
verifier.

The attestation application sends log records to a verifier.  There is
currently no standard transmission format.  The format must at least
provide means to recreate the original record so that hashes can be
verified. The verifier validates the log against the quote signature.

IMA Event Log Format
===================================

Multi-byte integer values (PCR index, length, etc.) are (by default)
in the byte order of the host where the event log was created,
**except where otherwise noted**. The sender can convert to network
byte order before transmission, as long as the values are not
hashed. For values that are hashed, the receiver must know the byte
order.

The :ref:`ima-canonical-fmt` boot command line argument forces the
byte order to little endian.

Sizes and lengths are always in bytes.

Fields are always concatenated with no padding.

The log has no specified maximum number of records. A faulty policy
that measures rapidly changing files like /var/log can have 100,000's
of records.  A reasonable policy will trigger about 5000 entries at
boot and the log can grow to 100,000 over time based on usage.

.. _ima-event-log-ascii-format:

IMA Event Log Ascii Format
===================================

.. warning::

   FIXME document the ascii format.

.. _ima-event-log-binary-format:

IMA Event Log Binary Format
===================================

The log can be displayed in human-readable for using the recipe at
:ref:`ima-log-parsing`.

An IMA event record has the following fields.

PCR Index
-----------------------------------

This is a 4-byte integer representing the PCR Index.

The default value is PCR 10.  See :ref:`config-ima-measure-pcr-idx`
and the policy rule condition :ref:`pcr-value`.

Due to :ref:`pcr-value`, the event log may contain events that have
not been extended.  E.g., the event log may contain PCR 17 or PCR 24.

.. _template-data-hash:

Template Data Hash
-----------------------------------

This is normally a hash of the :ref:`template-data` field. It can also
be all zeros.

   Exception: For the ``ima`` template name, the Template Data Hash is
   a SHA-1 hash of the File Data Hash field and the File Name padded
   with zero bytes to a length of 256 bytes. The File Name Length
   field is not hashed.

An all zeros hash indicates a measurement log violation.  IMA is
invalidating an entry.  Trust in entries after that are up to the end
user. If the Template Data Hash is all zeros, an all ones digest is
extended.

Cases include:

* if the policy rule includes :ref:`digest-type` ``=verity`` and the
  fs-verity digest is not present.

* if one process opens for read while another has it open for write.

There is no associated length or descriptor. The reader knows the
digest algorithm from the :ref:`ima-event-log-location`.

Template Name Length
-----------------------------------

This is a 4-byte integer representing the length of the Template Name
field.

Question: What is the maximum length?

Template Name
-----------------------------------

This is a printable string representing the template name.

The string is NOT nul terminated. It is guaranteed to be printable.

For legal names, see :ref:`built-in-templates` and
:ref:`template-data-fields`.

Template Data Length
-----------------------------------

This is a 4-byte integer representing the length of the Template Data
field.

   Note that there is redundancy, in that the data fields are
   self-describing. This can be checked for consistency.

.. _template-data:

Template Data
-----------------------------------

See `Template Data Fields`_ for the contents of this field.

The template is specified in this order:

* Compile time :ref:`config-ima-default-template`
* Boot time :ref:`template-specifiers`
* Policy rule :ref:`template`

.. _built-in-templates:

Built-in Templates
===================================

The predefined / built-in template names below can be

* compiled in with :ref:`config-ima-default-template`
* specified with :ref:`boot-command-line-arguments`
* specified within a policy rule using :ref:`template`

``|`` is the concatenation symbol.

=================== =========================================================================================================================
Field	            Built-in Templates Using the Field
------------------- -------------------------------------------------------------------------------------------------------------------------
:ref:`d`            :ref:`ima`
------------------- -------------------------------------------------------------------------------------------------------------------------
:ref:`n`            :ref:`ima`
------------------- -------------------------------------------------------------------------------------------------------------------------
:ref:`d-ng`         :ref:`ima-ng` , :ref:`ima-sig` , :ref:`ima-buf` , :ref:`ima-modsig` , :ref:`evm-sig`
------------------- -------------------------------------------------------------------------------------------------------------------------
:ref:`n-ng`         :ref:`ima-ng` , :ref:`ima-sig` , :ref:`ima-buf` , :ref:`ima-modsig` , :ref:`ima-ngv2` , :ref:`ima-sigv2` , :ref:`evm-sig`
------------------- -------------------------------------------------------------------------------------------------------------------------
:ref:`sig`          :ref:`ima-sig` , :ref:`ima-modsig` , :ref:`ima-sigv2`
------------------- -------------------------------------------------------------------------------------------------------------------------
:ref:`buf`          :ref:`ima-buf`
------------------- -------------------------------------------------------------------------------------------------------------------------
:ref:`d-modsig`     :ref:`ima-modsig`
------------------- -------------------------------------------------------------------------------------------------------------------------
:ref:`modsig`       :ref:`ima-modsig`
------------------- -------------------------------------------------------------------------------------------------------------------------
:ref:`d-ngv2`       :ref:`ima-ngv2` , :ref:`ima-sigv2`
------------------- -------------------------------------------------------------------------------------------------------------------------
:ref:`evmsig`       :ref:`evm-sig`
------------------- -------------------------------------------------------------------------------------------------------------------------
:ref:`xattrnames`   :ref:`evm-sig`
------------------- -------------------------------------------------------------------------------------------------------------------------
:ref:`xattrlengths` :ref:`evm-sig`
------------------- -------------------------------------------------------------------------------------------------------------------------
:ref:`iuid`         :ref:`evm-sig`
------------------- -------------------------------------------------------------------------------------------------------------------------
:ref:`igid`         :ref:`evm-sig`
------------------- -------------------------------------------------------------------------------------------------------------------------
:ref:`imode`        :ref:`evm-sig`
=================== =========================================================================================================================


.. _`ima`:

ima
-----------------------------------

  SHA-1 digest and file name.

  :ref:`d` \| :ref:`n`

.. _`ima-ng`:

ima-ng
-----------------------------------

  Digest and file name.

  :ref:`d-ng` \| :ref:`n-ng`

.. _`ima-sig`:

ima-sig
-----------------------------------

  Digest, file name, and signature.

  d-ng_ \| n-ng_ \| sig_

.. _`ima-buf`:

ima-buf
-----------------------------------

  d-ng_ \| n-ng_ \| buf_

  The :ref:`func-kexec-cmdline`, :ref:`func-key-check`, and
  :ref:`func-critical-data` policy rules force this template

.. _`ima-modsig`:

ima-modsig
-----------------------------------

  d-ng_ \| n-ng_ \| sig_ \| d-modsig_ \| modsig_

  Note: This template has two digest fields,  d-ng_ and d-modsig_,
  and two signature fields, sig_ and modsig_.

  Note that:

  * This template is only used for :ref:`appended-signatures`.

  * The d-modsig_ and modsig_ fields are only populated if both
    the ``measure`` and ``appraise`` rules trigger. They are
    not independent in this case.

  * The d-modsig_ and modsig_ fields are only populated if there
    is an appended signature.

  * It triggers on :ref:`func-kexec-kernel-check` and
    :ref:`func-module-check`, but does not trigger for
    :ref:`func-file-check`.

See :ref:`func-module-check` for kernel module appraisal details. See
:ref:`func-kexec-kernel-check` for kexec appraisal details.


.. _`ima-ngv2`:

ima-ngv2
-----------------------------------

  d-ngv2_ \| n-ng_

.. _`ima-sigv2`:

ima-sigv2
-----------------------------------

  d-ngv2_ \| n-ng_ \| sig_

.. _`evm-sig`:

evm-sig
-----------------------------------

  d-ng_ \| n-ng_ \| evmsig_ \| xattrnames_ \| xattrlengths_ \| xattrvalues_ \| iuid_ \| igid_ \| imode_

.. _template-data-fields:

Template Data Fields
===================================

Template data can have the following fields. Unless specified, each is
preceded by a 4-byte length.  Each entry is separated by a ``|``
character and no spaces.

What happens if a field appears multiple times?


.. _d:

d
-----------------------------------

``d`` is 20-byte digest, SHA-1 or zero padded MD-5 (no length)

.. _d-ng:

d-ng
-----------------------------------

``d-ng`` is a :ref:`hash-length` + :ref:`hash-algorithm` +
:ref:`file-data-hash`.


The :ref:`file-data-hash` is similar to :ref:`d-modsig`. The hash
input includes the appended signature if present in the file.

   Note: A file signature verifier should use a hash of the file
   excluding the appended signature.

.. _hash-length:

Hash Length
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is a 4-byte integer representing the combined length of the
:ref:`hash-algorithm` and :ref:`file-data-hash` fields. Those fields
do not have explicit lengths.

.. _hash-algorithm:

Hash Algorithm
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is a string representing the hash algorithm of the
File Data Hash field. The values are the same as those
of :ref:`ima-hash` in the :ref:`boot-command-line-arguments`.

In the event log, the algorithm is followed by a ``:`` and a nul
terminator.

   Note this redundancy, which can be checked for consistency:

-  The Hash Length minus the length of the Hash Algorithm field
   (including the nul terminator) yields the size of the File Data Hash.

-  The length of a hash based on the Hash Algorithm yields the size of
   the File Data Hash.

.. _file-data-hash:

File Data Hash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is a hash of the file data. It can be either the IMA digest (a
digest of the entire file) or the fs-verity digest. An all zeros hash
indicates a measurement log violation.

   Note that the fs-verity digest can also include an appended signature.

For :ref:`d-ng` and :ref:`d-ngv2`, the hash input includes an appended signature, if
present. Therefore, it cannot be used to verify the signature sig_ of a
file with an appended signature.

For :ref:`d-modsig`, the hash input does not include the appended signature.
It can be used to verify the signature sig_ of a file with an appended
signature.

The length and hash algorithm are determined by the :ref:`hash-algorithm`
field.

.. _d-modsig:
  
d-modsig
-----------------------------------

``d-modsig`` is a :ref:`hash-length` + :ref:`hash-algorithm` +
:ref:`file-data-hash`. It is similar to d-ng_, but the input to the
:ref:`file-data-hash` omits the appended signature. It is used to
verify the appended signature.

   Note: In order to check the modsig_ signature, d-modsig_ (the hash)
   must be included in the measurement list.  The :ref:`ima-modsig`
   template does this.

When there is no appended signature, this field will have a
:ref:`hash-length` of zero.

.. _d-ngv2:

d-ngv2
-----------------------------------

``d-ngv2`` contains a 4-byte length + prefix + hash algorithm +
:ref:`file-data-hash`. The length is that of the prefix and hash
algorithm, the nul terminator, and the digest.

See :ref:`ima-hash` for hash algorithm strings.

The legal values for the prefix, determined by the :ref:`digest-type`
policy rule, are:

* ``ima:``
* ``verity:``

.. warning::

   What is the maximum length of the prefix?

Examples of the prefix and hash algorithm are below. There is one nul
terminator after the second ``:``.

::

   ima:sha256:
   verity:sha256:

.. _n:

n
-----------------------------------

``n`` is a file name within the :ref:`ima` template. ``n`` cannot be used
in a custom template.

Unlike :ref:`n-ng`:

* The file name is not nul terminated.
* If the length is greater than 255, the path is removed and only the
  file name is recorded.

See :ref:`n-ng` :ref:`file-name` for the description.

.. _n-ng:

n-ng
-----------------------------------

File Name Length
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is a 4-byte integer representing the length of the file name,
including the nul terminator. The maximum value is MAXPATHLEN +1,
currently 4097.

   Note that there is often redundancy, in that the file name is nul
   terminated. This can be checked for consistency.

.. _file-name:

File Name
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For ``n-ng``, this is a nul terminated string representing the name of
the file that was measured.

The file name accurately records the full path that the kernel used to
access the file. Because that path can be a hard or soft link, it may
not represent the actual file location.

The file name is useful for forensics when the verifier detects an
error.  Typical errors are:

* a file data hash is not on an approved list
* the file is not signed when required
* the file is signed with an unknown public key
* the file signature verification failed

.. _sig:

sig
-----------------------------------

This field contains the file :ref:`signature`. This field describes
the :ref:`signature-hash-algorithm`.  The signature algorithm is
derived from the public key, which is in turn derived from the
:ref:`public-key-identifier`.

This field holds the extended attribute signature, never the appended
signature.  See :ref:`modsig`.

For the :ref:`extended-verification-module`, it holds the signature
over the meta-data.

* If ``security.ima`` has a file data signature, it is used.

* Else, if ``security.ima`` has a hash, then

   - If ``security.evm`` is a portable signature, it is used.

   - Else there is no signature.

The ``security.evm`` portable signature is over the file meta-data.

An example for add a ``security.evm`` portable signature is at
:ref:`evmctl-portable-signature`.

IMA supports several signature algorithms, including:

* RSA-2048
* ECDSA
* ECRDSA (GOST)
* SM2

.. _signature-length:

Signature Length
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is a 4-byte integer representing the total length of the Signature
Header and Signature fields. The value may be zero, indicating that
those two fields are not present.

Signature Header
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This field is fixed at 9 bytes, consisting of 5 fields.

* :ref:`signature-type`
* :ref:`signature-version`
* :ref:`signature-hash-algorithm`
* :ref:`public-key-identifier`
* :ref:`signature-size`

These fields do not encode the signature algorithm. That is determined
by mapping the :ref:`public-key-identifier` to the signing
certificate, which contains the signature algorithm.


.. _signature-type:

Signature Type
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This is a 1-byte field.

The legal values are:

* ``0x03`` EVM_IMA_XATTR_DIGSIG

  For this value, the :ref:`signature-version` is always 0x02.

* ``0x05`` EVM_XATTR_PORTABLE_DIGSIG

  This indicates that the signature is the portable signature of EVM
  file meta-data.

* ``0x06`` IMA_VERITY_DIGSIG

  This introduces a level of indirection. Instead of directly signing
  the fs-verity digest, the signature is of the hash of the type of
  data (e.g. fs-verity) and the digest. :ref:`signature-version` is
  always 0x03.

.. _signature-version:

Signature Version
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This is a 1-byte field.

The legal values are:

* ``0x02`` file digest
* ``0x03`` verity file digest

.. _signature-hash-algorithm:

Hash Algorithm
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This is a 1-byte field representing the hash algorithm used for the File
Data Hash.

The values are:

- ``0x00``: MD4
- ``0x01``: MD5
- ``0x02``: SHA-1
- ``0x03``: RIPEMD-160
- ``0x04``: SHA-256
- ``0x05``: SHA-384
- ``0x06``: SHA-512
- ``0x07``: SHA-225
- ``0x08``: RIPEMD-128
- ``0x09``: RIPEMD-256
- ``0x0a``: RIPEMD-320
- ``0x0b``: Whirlpool-256
- ``0x0c``: Whirlpool-384
- ``0x0d``: Whirlpool-512
- ``0x0e``: Tiger-128	(removed from kernel)
- ``0x0f``: Tiger-160	(removed from kernel)
- ``0x10``: Tiger-192	(removed from kernel)
- ``0x11``: SM3-256
- ``0x12``: Streebog-256
- ``0x13``: Streebog-512

   Note that there is redundancy, in that this field must be consistent
   with the Hash Algorithm field on the Template Data.

.. _public-key-identifier:

Public Key Identifier
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This is a 4-byte field that identifies the public key. It is the last 4
bytes of the key's X.509 certificate Subject Key Identifier.

.. _signature-size:

Signature Size
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This is a 2-byte integer representing the size of the Signature field
in **big endian** format.

    Note that there is redundancy, in that this field must be
    consistent with the signing public key pointed to by the
    :ref:`public-key-identifier`.

.. _log-signature:

Signature
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This field represents the signature over the File Data Hash using the
key specified by the Public Key Identifier and the hash algorithm
represented by the (two) Hash Algorithm fields, the signature
:ref:`signature-hash-algorithm` and the file data
:ref:`hash-algorithm`.

* RSA - a raw RSA signature
* ECC - a DER encoded SEQUENCE containing the R and S integers.

.. _evmsig:

evmsig
-----------------------------------

``evmsig`` follows the format of :ref:`sig`.  The
:ref:`signature-type` is ``0x05`` EVM_XATTR_PORTABLE_DIGSIG.

If a signature exists in ``security.ima`` it is stored.  Otherwise,
the signature in ``security.evm`` is stored.

.. _buf:

buf
-----------------------------------

``buf`` is a 4 byte length plus a buffer.

.. warning::

   What is the maximum length of this field?

The buffer contains a variable length buffer whose contents is
determined by the :ref:`n-ng` field. The :ref:`n-ng` field
is not a file name.

These policy rules create a non-zero length ``buf``.

::

   measure func=KEY_CHECK
   measure func=CRITICAL_DATA
   measure func=KEXEC_CMDLINE

.. _buf-key-check:

func=KEY_CHECK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When triggered by the measure :ref:`func-key-check` policy rule, it
measures data as it is loaded on different :ref:`keyrings`. The
:ref:`n-ng` field is the nul terminated name of the keyring.

``buf`` can be a DER encoded X.509 IMA certificate or a
:ref:`dot-blacklist` hash.

.. warning::

   A sample had a 32-byte value which appeared to be a hash. If so,
   where does the hash algorithm come from?

.. _buf-critical-data:

func=CRITICAL_DATA
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When triggered by the measure :ref:`func-critical-data` policy rule,
it measures data such as the SELinux state. The :ref:`n-ng` field
may be:

* ``selinux-state`` - a non-nul terminated string holding the SELinux
  state
* ``selinux-policy-hash``

* ``dm_table_load``

   - ``dm_version`` =n.n.n;
   - device metadata

      + ``name`` =device name,
      + ``uuid`` =uuid,
      + ``major`` =n,
      + ``minor`` =n,
      + ``minor_count`` =n,
      + ``num_targets`` =n;

   - table_load_data

      + ``target_index`` =n,
      + ``target_begin`` =n,
      + ``target_len`` =n,
      + ``target_name`` =[linear/crypt/integrity],
      + ``target_version`` =n.n.n
      + ``device_name`` =n:n,``start`` =n;

* ``dm_device_resume``

   - ``dm_version`` as above
   - device metadata as above

   - ``active_table_hash`` = hash algorithm : hash;
   - ``current_device_capacity`` =n;

* ``kernel_version`` version string

.. warning::

   Define all n-ng field names and the meaning of the strings.

func=KEXEC_CMDLINE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When triggered by the measure :ref:`func-kexec-cmdline` policy rule
and a kexec() call, the :ref:`n-ng` field is

* ``kexec-cmdline``

``buf`` is a non-nul terminated string of boot command line arguments.


.. warning::

   document the ``boot_aggregate`` measurement somewhere.  What triggers it?

.. _modsig:

modsig
-----------------------------------

``modsig`` is a PKCS#7 DER encoding of the appended signature. See the CMS
document as in RFC 5652.

For appended signatures, ``modsig`` typically requires :ref:`d-modsig`,
the :ref:`file-data-hash` calculated omitting the appended signature.

When there is no appended signature, this field will have a length of
zero.

See the :ref:`ima-modsig` template for limitations.  The
:ref:`sign-file-appended-signature` utility can add an appended
signature.


.. _uuid:

uuid
-----------------------------------

.. warning::

    (undocumented)

.. _iuid:

iuid
-----------------------------------

``iuid`` is a 4-byte length plus the file user ID as in etc/passwd.

This measures the user ID of the original, actual file, not the
idmapped user ID within a container.

The length will be zero if the file being measured is not a
file. Examples are the boot aggregate or critical data.


.. _igid:

igid
-----------------------------------

``iuid`` is a 4-byte length plus the file group ID as in etc/passwd.

This measures the group ID of the original, actual file, not the
idmapped group ID within a container.

The length will be zero if the file being measured is not a
file. Examples are the boot aggregate or critical data.

.. _imode:

imode
-----------------------------------

``imode`` is a 4-byte length plus the file mode (e.g., user, group,
other).

The length will be zero if the file being measured is not a
file. Examples are the boot aggregate or critical data.

.. _xattrnames:

xattrnames
-----------------------------------

``xattrnames`` is a 4-byte length and a nul terminated text list of
xattr names (separated by ``|``).  The length can be zero if no xattrs
are present.

   Note: :ref:`xattrnames`, :ref:`xattrlengths`, and
   :ref:`xattrvalues` must be specified together.

For example names, see :ref:`extended-verification-module`.

   Note: There is redundancy that should be validated by the verifier.

   * The 4-byte length should equal the string length plus one for the
     nul terminator.


.. warning::

   This documentation needs a full specification of for each name's
   contents.

.. _xattrlengths:

xattrlengths
-----------------------------------

``xattrlengths`` is a 4-byte length plus a list of the 4-byte lengths
of the :ref:`xattrvalues` fields. The order of the lengths is
determined by the order of the :ref:`xattrnames`.

   Note: :ref:`xattrnames`, :ref:`xattrlengths`, and
   :ref:`xattrvalues` must be specified together.

   Note: There is redundancy that should be validated by the verifier.

   * The ``xattrlengths`` length should be a multiple of 4.
   * The number of :ref:`xattrnames` should equal the value of the
     ``xattrlengths`` length divided by 4.

.. _xattrvalues:

xattrvalues
-----------------------------------

``xattrvalues`` is a 4-byte length of all the values plus a list of
values. The order and content of the values are determined by the
:ref:`xattrnames` field.  Their lengths are determined by the
:ref:`xattrlengths` field.

   Note: :ref:`xattrnames`, :ref:`xattrlengths`, and
   :ref:`xattrvalues` must be specified together.

   Note: There is redundancy that should be validated by the verifier.

   * The sum of the 4-byte lengths of the :ref:`xattrvalues` fields
     should equal the 4-byte length of the :ref:`xattrvalues` field.

Integer Format
===================================

Multi-byte integer values (PCR index, length, etc.) are in the byte
order of the host where the event log was created. The sender can
convert to network byte order before transmission, as long as the values
are not hashed. For values that are hashed, the receiver must know the
byte order.

Sizes and lengths are always in bytes.

Fields are always concatenated with no padding.

