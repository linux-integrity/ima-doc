===================================
HOWTO
===================================

.. warning::

     This section is under construction.

The intent is to provide command line samples that link to tasks
described elsewhere.  It is **not** to duplicate the usage help or man
pages.

.. _evmctl:

evmctl
===================================

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

.. _evmctl-portable-signature:

evmctl portable signature
-----------------------------------

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

.. _evmctl-policy-signature:

evmctl policy signature
-----------------------------------

To generate an unencrypted private key (non-protected):

::

   openssl genrsa -out rsa_private.pem 2048

To generate the public key:

::

   openssl rsa -pubout -in rsa_private.pem -out rsa_public.pem

To sign the IMA :ref:`custom-policy`:

::

   evmctl ima_sign --hashalgo sha256 --key privkey_ima.pem policy

To sign all kernel modules with an IMA signature:

::

   find /lib/modules -name \*.ko -type f -uid 0 -exec evmctl ima_sign --key rsa_private.pem '{}' \;

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

evmctl fsverity signature
-----------------------------------


.. warning::

   Needs a review.

   Sample fsverity measurement list w/signature

   Before running the ima-evm-utils fsverity.test, generate keys using
   genkeys.sh. Make sure that "test-rsa2048.key" is created.  Run the
   test and then grep the ascii_runtime_measurements for "verity".

.. _keyctl:

keyctl
===================================

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

.. _keyctl-show:

keyctl show
-----------------------------------

``show`` lists keys on one of the :ref:`keyrings`.

Show the keys on the :ref:`dot-machine` keyring

::

   keyctl show %keyring:.machine
   keyctl show %keyring:.platform

To see if one of the :ref:`keyrings` exists:

::

   cat /proc/keys | grep platform


keyctl add key to keyring
-----------------------------------

.. warning::

   Incomplete notes on building a kernel with additional keys:

   Create self signed key and certificate

   privkey_ima.pem signing key
   x509_ima.der pubkey cert signed by ca key, self signed?

   change to 2048, sha256

   > ima-gen-local-ca.sh
   > ima-genkey.sh

   > git clone Linux kernel from git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable

   > cd linux-stable

    Build ca key into builtin keyring

    Edit ~/kernelbuild/linux514/.config

    CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"
    CONFIG_SYSTEM_TRUSTED_KEYRING=y
    CONFIG_SYSTEM_TRUSTED_KEYS="certs/trusted_keys.pem"

    cp ~/ima-evm-utils/examples/ima-local-ca.pem trusted_keys.pem

    keyctl show %keyring:.builtin_trusted_keys

    > make -j 24 O=../kernelbuild/linux514

    # make modules_install install O=../kernelbuild/linux514


    import ima public key certificate

    Fancy automated way of getting the magic number:

    bash::

       function get_keyid () {
          keyctl describe %keyring:$1 | sed 's/\([^:]*\).*/\1/'
       }

    keyrings are:

    .builtin
    .ima

    If builtin signs .ima
    If not builtin, ?

    keyctl show %keyring:.ima

	get the magic number from .ima

    evmctl import x509_ima.der 139899697
    keyctl show %keyring:.ima

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
Linux kernel and initramfs.  The signature format format is
PKCS#7.

::

   openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv -outform DER -out MOK.der -nodes -days 36500 -subj "/CN=Subject/"
   openssl x509 -text -inform der -in MOK.der -noout
   /usr/src/kernels/`uname -r`/scripts/sign-file sha256 ./MOK.priv ./MOK.der /boot/vmlinuz-6.1.6-200.fc37.x86_64
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


.. _mokutil:

mokutil
===================================

Package:

* Fedora - mokutil

.. warning::

   Add examples for registering .machine keys. .platform keys

   https://lwn.net/Articles/868595/

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

Package:

* RedHat, Fedora - pesign

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

..

   tssimaextend -le -sim -v -if filename

* -le indicates a little endian log.  Omit for the (rare) big endian log.

* -sim indicates that simulated PCR values should be calculated, as
  opposed to extending to a TPM.
* -v requests a verbose trace of the events
* -filename indicates the location of the log, which can be
  ``/sys/kernel/security/ima/binary_runtime_measurements``, but is
  often saved on a file for debugging.