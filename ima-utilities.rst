===================================
HOWTO
===================================

.. warning::

     This section is under construction.

The intent is to provide command line samples that link to tasks
described elsewhere.  It is **not** to duplicate the usage help or man
pages.

Utility Installation
===================================

.. _keyctl:

keyctl
-----------------------------------

Package:

* Fedora - keyutils

* Build from source

.. warning::

   These are just notes.  Provide sample use cases.

   keyctl add encrypted evm-key "new default user:kmk 32 $evmkey" @u

   evm-key is the HMAC key.

   Load keys on secondary_trusted_keys keyring.

   https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/security/keys/trusted-encrypted.rst

   https://www.kernel.org/doc/html/v4.15/admin-guide/module-signing.html

   Add a key:

   cat /proc/keys

   keyctl padd asymmetric "" [.system_keyring-ID] <[key-file]
   keyctl padd asymmetric "" 0x223c7853 <my_public_key.x509


.. _evmctl:

evmctl
-----------------------------------

Package:

* Fedora: ima-evm-utils
* Ubuntu: ima-evm-utils

   Note: The latest ``evmctl`` has an fs-verity test for the
   :ref:`digest-type` policy condition.

   This repo is at https://github.com/mimizohar/ima-evm-utils.git.  The
   utility is installed in ``/usr/local/bin``. Build and test as follows:

::

   autoreconf -i
   ./configure
   make
   sudo make install
   cd tests
   ./fsverity.test

.. warning::

   Add the configure rule for OpenSSL 3.x deprecated functions.

 .. _mokutil:

mokutil
-----------------------------------

Package:

* Fedora - mokutil
* Ubuntu - mokutil

.. _evmctl-portable-signature:

evmctl portable signature
===================================

To create a portable :ref:`evm-signature`, use this example.  It needs
root because it writes ``security.evm``.

::

   evmctl sign --imahash --portable --key <privkey.pem>  <pathname>

The ``hash`` output is written to ``security.ima``.  The ``evm/ima
signature`` output is written to ``security.evm``. The format of the
IMA and EVM signatures is the same as that of the event log :ref:`sig`
field, a header and a signature.

The result can be viewed with

::

    getfattr -m - -e hex -d  <pathname>

evmctl fsverity signature
===================================


.. warning::

   Needs a review.

   Sample fsverity measurement list w/signature

   Before running the ima-evm-utils fsverity.test, generate keys using
   genkeys.sh. Make sure that "test-rsa2048.key" is created.  Run the
   test and then grep the ascii_runtime_measurements for "verity".

.. _keyctl-show:

View a keyring
===================================


``keyctl show`` lists keys on one of the :ref:`keyrings`.

::

   keyctl show %keyring:.builtin_trusted_keys

::

   keyctl show %keyring:.secondary_trusted_keys

::

   keyctl show %keyring:.machine

::

   keyctl show %keyring:.platform

::

   keyctl show %keyring:.ima

The output data includes

* Subject CN - as text
* X509v3 Subject Key Identifier - as hexascii

To see if one of the :ref:`keyrings` exists:

::

   cat /proc/keys | grep platform


Build Kernel with IMA CA Key on keyring
==========================================

This procedure builds a kernel with the
:ref:`ima-ca-key-and-certificate` on the
:ref:`dot-builtin-trusted-keys` keyring. The key can be used to verify
loading of an :ref:`ima-signing-key` on the :ref:`dot-ima` keyring.

First create the IMA CA key and self signed certificate.  See
:ref:`ima-ca-key-and-certificate` for the creation and conversion
steps, but omit the ``mokutil --import`` step.

Clone the Linux kernel.

::

   git clone git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable
   cd linux-stable

Get the other branches and tags.

::

   git remote update origin

Go to the branch corresponding to the current system.  E.g.,

::

   git checkout --track -b linux-6.8.y origin/linux-6.8.y

Create a build directory and a subdirectory for the IMA CA
certificate.  E.g.,

::

   mkdir -p ../kernelbuild/linux-6.8.y/certs

The build configuration file is typically created by copying and
modifying an existing one.  E.g.,

::

   cp /boot/config-6.8.11-300.fc40.x86_64 ../kernelbuild/linux-6.8.y/.config

Concatenate the CA certificates created in
:ref:`ima-ca-key-and-certificate`.  E.g.,

::

   cat imacacert.pem imacacertecc.pem > ../kernelbuild/linux-6.8.y/certs/imacacerts.pem

Edit the ``../kernelbuild/linux-6.8.y/.config`` file and add the IMA
CA certificates, e.g.,

::

   CONFIG_SYSTEM_TRUSTED_KEYS="certs/imacacerts.pem"

Build the new Linux kernel.

::

   make localmodconfig O=../kernelbuild/linux-6.8.y
   make -j 8 O=../kernelbuild/linux-6.8.y

Copy the results to ``\boot``.

::

   sudo make modules_install install O=../kernelbuild/linux-6.8.y

.. _sign-file:

sign-file
===================================

Package:

* Fedora - kernel-devel
* Ubuntu - linux-headers-\`uname -r\`-generic 

Location:

* Fedora - /usr/src/kernels/\`uname -r\`/scripts/sign-file
* Ubuntu - /usr/src/linux-kernel-headers-\`uname -r\`/scripts/sign-file

Use ``sign-file`` to add an appended signature to a kernel module, a
kernel image, or an initramfs.  These items support the :ref:`ima-modsig`
template.  See :ref:`sign-file-appended-signature` for an example.

.. _sign-file-appended-signature:

sign-file appended signature
----------------------------------

Appended signatures can be measured and appraised with the
:ref:`func-module-check`, :ref:`func-kexec-kernel-check`, and
:ref:`func-kexec-initramfs-check` rules but **not** with the
:ref:`func-file-check` rule.

This example creates a signing key and an appended signature for a
Linux kernel and initramfs.  The signature format format is PKCS#7.

Create a signing key.

::

   openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv -outform DER -out MOK.der -nodes -days 36500 -subj "/CN=Subject/"

View the key.

::

   openssl x509 -text -inform der -in MOK.der -noout

Sign with the private key.

::

   /usr/src/kernels/`uname -r`/scripts/sign-file sha256 ./MOK.priv ./MOK.der /boot/vmlinuz-6.1.6-200.fc37.x86_64

::

   /usr/src/kernels/`uname -r`/scripts/sign-file sha256 ./MOK.priv ./MOK.der /boot/initramfs-6.1.6-200.fc37.x86_64.img

This kexec command does a soft boot, triggering measure and appraise
rules for testing.

::

   kexec -l -s /boot/vmlinuz-6.1.6-200.fc37.x86_64 --initrd /boot/initramfs-6.1.6-200.fc37.x86_64.img --reuse-cmdline


verify-file
===================================

.. warning::

   sign-file is part of the kernel, but verify-file is not.  How does
   one verify a signature other than with an appraise rule?

.. _xz:

xz
===================================

Package:

* Fedora - xz
* Ubuntu - xz-utils

Use the ``xy`` utility to unzip a kernel module ``.ko.xz`` to view an
appended signature.  Unzip in a /tmp directory.  See
:ref:`func-module-check` for a use case.

Example:

::

   cp /lib/modules/`uname -r`/kernel/crypto/wp512.ko.xz /tmp
   cd /tmp
   xz -d -k -v wp512.ko.xz
   tail wp512.ko


.. _sb-state:

Secure Boot State
===================================


``mokutil`` can be used to probe the secure boot state.

::

   mokutil --sb-state

.. _kernel-signing-key-generation:

Kernel Signing Key Generation
===================================

This is a method for generating a kernel image signing key and loading
the certificate into the UEFI MOK database. At reboot, the public key
is loaded on the :ref:`dot-platform` keyring. The private key and
certificate are stored in a database at ``/etc/pki/pesign``.

Run as ``root``.

View the existing keyring:

::

   keyctl show %:.platform

Create the signing key and certificate to be enrolled. By default,
they are put in ``/etc/pki/pesign`` databases.

::

   efikeygen --ca --self-sign --nickname="mokcert" --common-name='CN=MyCo' --serial=123

Export the certificate from the database to a file.

::

   certutil -L -d /etc/pki/pesign -n "mokcert" -o mokcert.der -r

Import the certificate into the MOK.  This stages the certificate.

::

   mokutil --import ./mokcert.der

Reboot. A UEFI prompt should appear. Accept the certificate, using the
password from ``mokutil``.

.. note::

   **The MOK prompt lasts for only a few seconds. Be at the machine
   during the reboot. If the prompt is missed and the machine boots,
   start over.**

View the updated MOK:

::

   mokutil -l

View the updated keyring:

::

   keyctl show %:.platform

.. note::

   With the --ca argument, the certificate attributes are

   ::

      	Digital Signature, Certificate Sign, CRL Sign
                CA:TRUE

   Without the --ca argument, the certificate attributes are

   ::

      Digital Signature, Key Encipherment, Data Encipherment

.. note::

   Non-root experiments can be performed as below, creating a tmp
   directory.  The ``pki`` utility is in

   * Fedora: dogtag-pki-tools
   * Ubuntu: pki-tools

   ::

	pki -c pwd -d tmp client-init
        efikeygen --ca --self-sign --nickname="mokcert" --common-name='CN=MyCo' --serial=123 -d tmp
        certutil -L -d tmp -n "mokcert" -o mokcert.der -r
        openssl x509 -inform der -in mokcert.der -noout -text

.. _mok-certificate-export:

MOK Certificate Export
===================================

``mokutil`` can be used to export a certificate from the MOK.

Run as ``root``.

::

   mokutil --export

The certificates are exported in ``der`` format.  A certificate can be
viewed using, e.g.,

::

   openssl x509 -inform der -in MOK-0005.der -text -noout

.. _-mok-certificate-delete:

MOK Certificate Delete
===================================

``mokutil`` can be used to delete (the opposite of import) a
certificate from the MOK and the :ref:`dot-machine` and
:ref:`dot-platform` keyrings.

Run as ``root``.

View the existing keyring:

::

   keyctl show %:.platform

If the ``der`` format certificate is not available, use
:ref:`mok-certificate-export` to export and view the
certificates. Chose the certificate to be deleted.

This is the first step in deleting the certificate, specifying a
deletion password:

::

   mokutil --delete MOK-000n.der

Check using:

::

   mokutil --list-delete

Then reboot.

.. note::


   **The MOK prompt lasts for only a few seconds. Be at the machine
   during the reboot. If the prompt is missed and the machine boots,
   start over.**


Follow the prompt steps, entering the password, and then let the
platform boot.

Confirm by viewing the keyring.

.. _ima-ca-key-and-certificate:

IMA CA Key and Certificate
===================================

The IMA CA key signs the :ref:`ima-signing-key`, which is used to sign
files. The IMA CA certificate is installed on the
:ref:`dot-builtin-trusted-keys`, :ref:`dot-secondary-trusted-keys`, or
:ref:`dot-machine` keyring.

Note: This requires secure boot to be enabled, and
:ref:`config-integrity-platform-keyring` and
:ref:`config-integrity-ca-machine-keyring-max` set.

Create the CA signing key and CA certificate using OpenSSL.  The key
usage will be ``Certificate Sign``.  E.g.,

Create a configuration file similar to this sample imacacert.cfg:

::

  [ req ]
  distinguished_name = issuer_dn
  prompt = no
  string_mask = utf8only
  x509_extensions = extensions

  [ issuer_dn ]
  O = IMA-CA
  CN = IMA/EVM certificate signing key
  emailAddress = ca@ima-ca.com

  [ extensions ]
  basicConstraints=CA:TRUE
  subjectKeyIdentifier=hash
  authorityKeyIdentifier=keyid:always,issuer
  keyUsage = cRLSign, keyCertSign

Generate an RSA-3072 CA key and certificate:

::

   openssl req -new -x509 -out imacacert.pem -sha256 -pkeyopt rsa_keygen_bits:3072 -days 3650 -batch -config imacacert.cfg -keyout imacakey.pem

Generate an ECC P256 CA key and certificate:

::

   openssl req -x509 -out imacacertecc.pem -newkey ec -pkeyopt ec_paramgen_curve:secp256k1 -days 3650 -keyout imacakeyecc.pem -config imacacert.cfg 

Convert the certificate from ``pem`` to ``der`` format.

::

   openssl x509 -in imacacert.pem -out imacacert.der -outform der
   openssl x509 -in imacacertecc.pem -out imacacertecc.der -outform der


Use ``mokutil`` to stage the certificate for appending to the MOK database.

::

      mokutil --import ./imacacert.der

::

      mokutil --import ./imacacertecc.der

Reboot. A UEFI prompt should appear. Accept the certificate, using the
password from ``mokutil``.

View the updated :ref:`dot-machine` keyring:

::

   keyctl show %:.machine

.. _ima-signing-key:

IMA Signing Key and Certificate
===================================

An IMA signing key signs files and other objects.  IMA :ref:`appraisal`
uses certificates that are installed on the :ref:`dot-ima` keyring.

Create the IMA signing key and certificate using OpenSSL.

For RSA-3072 and ECC P256.

::

   openssl genrsa -out imakeyrsa.pem 3072

::

   openssl ecparam -genkey -name prime256v1 -out imakeyecc.pem

Create the certificate signing requests for the RSA and ECC keys.

::

   openssl req -new -key imakeyrsa.pem -out imacsrrsa.pem

::

   openssl req -new -key imakeyecc.pem -out imacsrecc.pem


Create a configuration file similar to this sample imacert.cfg is:

::

   [ ext ]
   authorityKeyIdentifier = keyid:always,issuer:always
   basicConstraints = CA:false
   keyUsage = nonRepudiation, digitalSignature

Sign the certificate with the :ref:`ima-ca-key-and-certificate` for RSA-3072 and ECC P256.

::

   openssl x509 -req -in imacsrrsa.pem -CA imacacert.pem -CAkey imacakey.pem -outform der -out imacertrsa.der -days 365 -extensions ext -extfile imacert.cfg

::

   openssl x509 -req -in imacsrecc.pem -CA imacacert.pem -CAkey imacakey.pem -outform der -out imacertecc.der -days 365 -extensions ext -extfile imacert.cfg


View the resulting IMA signing key certificate:

::

   openssl x509 -in imacertrsa.der -inform der -noout -text

::

   openssl x509 -in imacertecc.der -inform der -noout -text

One Time Install
------------------------

Get the :ref:`dot-ima` keyring ID, the first number in the output of:

::

   keyctl show %keyring:.ima

Import the IMA signing key certificate onto the :ref:`dot-ima` keyring.

::

   evmctl import imacertrsa.der <keyring-ID>

::

   evmctl import imacertecc.der <keyring-ID>

   Verify the result.

::

   keyctl show %keyring:.ima


Persistent Install
--------------------

Move the IMA signing key certificate to the staging area.  It must be
in ``der``, not ``pem`` format.

::

   cp imacertrsa.der /etc/keys/ima

::

   cp imacertecc.der /etc/keys/ima

Modify the ``dracut`` module to load the IMA signing key
certificate. The location is
``/lib/dracut/modules.d/98integrity/module-setup.sh``

* Change the check() return to 0.
* Comment out the evm-enable.sh line

Rebuild initramfs with the modified script.  Using a bash shell:

::

   dracut --kver $(uname -r) --force --add integrity

Reboot.  Verify the result.

::

   keyctl show %keyring:.ima

.. note::

   To verify the inramfs update, run this is a temporary directory

   ::

       lsinitrd --unpack /boot/initramfs-$(uname -r).img

   and verify that
   ``./usr/lib/dracut/hooks/pre-pivot/61-ima-keys-load.sh`` exists.



.. _policy-signature:

Sign and Install a  Custom Policy
===================================

Use this to sign an IMA :ref:`custom-policy`: file.

See :ref:`ima-signing-key` to generate a signing private key and
install the verification certificate.

To sign the IMA :ref:`custom-policy`:

::

   evmctl ima_sign --hashalgo sha256 --key imakey.pem policy

To read the signature:

::

   getfattr -m - -e hex -d policy

To install the policy.  The policy path must start with ``\``.

::

   echo /home/rooted-path/policy > /sys/kernel/security/ima/policy


To sign all kernel modules with an IMA signature:

::

   find /lib/modules -name \*.ko -type f -uid 0 -exec evmctl ima_sign --key imakey.pem '{}' \;

.. warning::

   **FIXME Signature v1 support is being deprecated in
   ima-evm-utils. Refer to commit 751a3957729d ("Deprecate IMA
   signature version 1").**

To sign immutable files (like kernel modules and application code),
the ``evmctl`` command provided by the app-crypt/ima-evm-utils package
**FIXME needs link** needs be used. But first, set up the kernel
keyring:

::

   evmctl import --rsa rsa_public.pem $(keyctl newring _ima @u)

This allows the IMA subsystem to validate the signature (which is also
needed when initially setting the signature) by loading the public key
onto the IMA keyring. This needs to be done every time the system
boots, so it makes sense to do so within an initramfs (early in the
boot process).

.. warning::

   Explain -imahash vs -ima_sign.

   FIXME Merge samples from this documentation.

   https://en.opensuse.org/SDB:Ima_evm#The_evmctl_utility

   https://www.mankier.com/1/evmctl#Integrity_Keyrings

   https://github.com/mimizohar/ima-evm-utils

``evmctl`` was extended to pass file metadata using command line parameters:

..

  --ino          use custom inode for EVM
  --uid          use custom UID for EVM
  --gid          use custom GID for EVM
  --mode         use custom Mode for EVM
  --generation   use custom Generation for EVM(unspecified: from FS, empty: use 0)
  --ima          use custom IMA signature for EVM
  --selinux      use custom Selinux label for EVM
  --caps         use custom Capabilities for EVM(unspecified: from FS, empty: do not use)

.. warning::

   Remove usage help.  Instead provide examples for typical applications.





.. _pesign-database:

pesign Database
===================================

View the database.

::

   certutil -d /etc/pki/pesign -K

Export the certificate from the database to a file.

::

   certutil -L -d /etc/pki/pesign -n "mokcert" -o mokcert.der -r

Delete the key and certificate from the databases.

::

   certutil -d /etc/pki/pesign -F -n "mokcert"

To delete an orphan key (after deleting just the certificate),
where the fingerprint is listed with ``-K``.

::

   certutil -d /etc/pki/pesign -F -k fingerprint


.. _setfattr:

setfattr
===================================

``setfattr`` sets the extended attributes of filesystem objects.

.. warning::

   Add example that triggers :ref:`func-setxattr-check` when setting a
   hash algorithm.

   Add an example of setting the security.ima signature.

   possibly

   setfattr -n security.ima -v 0x12434567 executable.bin

fsverity
===================================

.. warning::

   Add example for signing an fs-verity digest and storing the
   signature in security.ima.

   Needs fs-verity enabled in the kernel.
   Needs fs-verity package.  fedora fsverity-utils
   IMA evmutils package contains fsverity.test

   Sample fsverity measurement list w/signature

   Before running the ima-evm-utils fsverity.test, generate keys using
   genkeys.sh. Make sure that "test-rsa2048.key" is created.  Run the
   test and then grep the ascii_runtime_measurements for "verity".

   Sample measurement log output:

   ::

       10 edee38d76b103e8823948d1a823296a46b44874c ima-sigv2 verity:sha256:f1a07ea07aa600a6eb4a61448ca16661a646356b9ff0b3b593b6796191173106 /tmp/fsverity-test/verity-hash.0Pc9Tz 0603046a098c9901004257cd57c26465ca1f97d03cdd403fcc0b05208e2a2ae20a6a9b96795a500d64fff0b0af914bf9268c98604ab26a746361a9bdf1f076dbaa0423ad05b6b5179e994a3188ef616e806ec8426cc0c158d1c7c0517793d71268536f84eec06b7fe81411f759896894428aae094fcee2239e0c370254a0250f51cb24de77d1d6a6f8f15a5b34fd1eec32748635947ceb005fb5a826ea6f30921200779be8283414f9794686ee169a4e89941eb4ae7bd366b75bcb7cb83ccda78b062bbfbd6de87c1e0275cfc68a31a116e7214863597ba9de67b6e957a511f5b5abddedcf57bb074fcb7b4eec7695b8600d36363ea43886278f76e1c7916c1cb90ceebefcd32a7587

.. _efikeygen:

efikeygen
===================================

his tool generates keys for PE image signing.

Package:

* RedHat, Fedora - pesign
* Debian, Ubuntu - pesign

See https://www.mankier.com/1/efikeygen


.. _ima_inspect:

ima-inspect
===================================

.. warning::

   https://github.com/mgerstner/ima-inspect does further parsing of the
   extended attributes.

   **FIXME Needs testing and a sample command line input and output.**

imaextend
===================================

``imaextend`` includes sereral functions related to the :ref:`ima-event-log`.

Package:

* Fedora: tss2
* Ubuntu: libtss0

.. _ima-log-parsing:

IMA log parsing
-------------------

The :ref:`ima-event-log-binary-format` can be displayed using this command:

::

   tssimaextend -le -sim -v -if filename

* -le indicates a little endian log.  Omit for the (rare) big endian log.

* -sim indicates that simulated PCR values should be calculated, as
  opposed to extending to a TPM.
* -v requests a verbose trace of the events
* -filename indicates the location of the log, which can be
  ``/sys/kernel/security/ima/binary_runtime_measurements``, but is
  often saved on a file for debugging.