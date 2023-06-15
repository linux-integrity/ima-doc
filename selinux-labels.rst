.. _selinux-labels:

SELinux Labels
--------------

Linux Security Modules (LSM) maintain file metadata, which can be
leveraged to limit the number of files measured.

IMA policy can filter on SELinux labels.

A file’s labels can be displayed with ``ls -1Z``. ``object_r:`` shows
the file’s label.

``seinfo -t`` displays all the possible labels.
``seinfo -a`` displays all the possible attributes.

``seinfo -afile_type -x`` displays all the possible file labels,
useful for constructing file policies.

These are useful for constructing exclusion rules (``dont_measure``,
``dont_appraise``) for files with unpredictable or changing data that
cannot be signed or validated against an approved list of
file hashes.  Examples are:

* ``seinfo -alogfile -x`` displays log files.
* ``seinfo -atmpfile -x`` displays temporary files.
* ``seinfo -aspoolfile -x`` displays spool files.
* ``seinfo -alockfile -x`` displays lock files.

Labels in the extended attribute can also be viewed
``security.selinux`` using

::

   getfattr -m - -d <file>

where ``-m -`` requests all attributes and ``-d`` dumps the values.

User ID labels (user, role, and domain) can be displayed with

::

   id -Z


.. _obj-type:

obj_type
~~~~~~~~~~~~~~~~~~~

``obj_type`` can be used in the policy rule :ref:`obj-type-equals`.

Example::

  dont_measure obj_type=var_log_t

======================= =====================================
SELinux Label		Typical use
-----------------------	-------------------------------------

acct_data_t		/var/account
admin_home_t		/root
autofs_t		/gsa /misc /net
bin_t			/bin /usr/bin /sbin /usr/sbin
boot_t			/boot
default_t		(before labeling)
device_t		/dev
dosfs_t			/boot/efi_t		/var/log
games_data_t            /var/games
httpd_sys_content_t     /var/www
kdump_crash_t           /var/crash
mail_spool_t            /var/mail -> spool/mail
mysql_db_t		/var/lib/mysql
public_content_t        /var/ftp
system_db_t             /var/db
tmp_t                   /var/tmp
var_t                   /var/adm /var/cache /var/local /var/empty /var/kerberos /var/nis  /var/opt /var/preserve
var_lib_t               /var/lib
var_log_t               /var/log
var_lock_t              /var/lock
var_run_t               /var/run
var_spool_t             /var/spool
var_yp_t		/var/yp

=======================	=====================================
