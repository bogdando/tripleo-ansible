#!/usr/bin/env python
#
# Copyright 2018 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import logging
import os
import pwd
import selinux
import stat
import sys

debug = os.getenv('__OS_DEBUG', 'false')

ALLOWED_UMASK = ['0o0', '0o2', '0o7', '0o22', '0o26', '0o27', '0o77', '0o277']
DEFAULT_UMASK = '0o027'
DEFAULT_DIR_MODE = '0o750'
DEFAULT_FILE_MODE = '0o640'

if debug.lower() == 'true':
    loglevel = logging.DEBUG
else:
    loglevel = logging.INFO

logging.basicConfig(stream=sys.stdout, level=loglevel)
LOG = logging.getLogger('nova_statedir')


class PathManager(object):
    """Helper class to manipulate ownership of a given path"""
    def __init__(self, path):
        self.path = path
        self.uid = None
        self.gid = None
        self.mode = None
        self.is_dir = None
        self.secontext = None
        self._update()

    def _update(self):
        try:
            statinfo = os.stat(self.path)
            self.is_dir = stat.S_ISDIR(statinfo.st_mode)
            self.uid = statinfo.st_uid
            self.gid = statinfo.st_gid
            self.mode = oct(statinfo.st_mode & 0o777)
            self.secontext = selinux.lgetfilecon(self.path)[1]
        except Exception:
            LOG.exception('Could not update metadata for %s', self.path)
            raise

    def __str__(self):
        return "uid: {} gid: {} mode: {} path: {}{}".format(
            self.uid,
            self.gid,
            self.mode,
            self.path,
            '/' if self.is_dir else ''
        )

    def has_owner(self, uid, gid):
        return self.uid == uid and self.gid == gid

    def has_mode(self, mode):
        return self.mode == oct(int(mode, 8) & 0o777)

    def has_either(self, uid, gid):
        return self.uid == uid or self.gid == gid

    def chown(self, uid, gid):
        target_uid = -1
        target_gid = -1
        src_uid = self.uid
        src_gid = self.gid
        if src_uid != uid:
            target_uid = uid
        if src_gid != gid:
            target_gid = gid
        if (target_uid, target_gid) != (-1, -1):
            try:
                os.chown(self.path, target_uid, target_gid)
                self._update()
                LOG.info('Changed ownership of %s from %d:%d to %d:%d',
                         self.path,
                         src_uid,
                         src_gid,
                         self.uid,
                         self.gid)
            except Exception:
                LOG.exception('Could not change ownership of %s: ',
                              self.path)
                raise
        else:
            LOG.info('Ownership of %s already %d:%d',
                     self.path,
                     uid,
                     gid)

    def chcon(self, context):
        # If dir returns whether to recursively set context
        try:
            try:
                selinux.lsetfilecon(self.path, context)
                LOG.info('Setting selinux context of %s to %s',
                     self.path, context)
                return True
            except OSError as e:
                if self.is_dir and e.errno == 95:
                    # Operation not supported, assume NFS mount and skip
                    LOG.info('Setting selinux context not supported for %s',
                             self.path)
                    return False
                else:
                    raise
        except Exception:
            LOG.exception('Could not set selinux context of %s to %s:',
                          self.path, context)
            raise

    def chmod(self, mode):
        target_mode = None
        src_mode = self.mode
        if src_mode != mode:
            target_mode = mode
        if target_mode != None:
            try:
                if type(target_mode) == str:
                    mode_octal = target_mode
                else:
                    mode_octal = oct(target_mode)
                os.chmod(self.path, int(mode_octal, 8) & 0o777)
                self._update()
                LOG.info('Changed permissions of %s from %s to %s',
                         self.path,
                         src_mode,
                         self.mode)
            except Exception:
                LOG.exception('Could not change permissions of %s: ',
                              self.path)
                raise
        else:
            LOG.info('Permissions of %s already %s',
                     self.path,
                     mode)


class NovaStatedirOwnershipManager(object):
    """Class to manipulate the ownership of the nova statedir (/var/lib/nova).

       The nova uid/gid differ on the host and container images. An upgrade
       that switches from host systemd services to docker requires a change in
       ownership. Previously this was a naive recursive chown, however this
       causes issues if nova instance are shared via an NFS mount: any open
       filehandles in qemu/libvirt fail with an I/O error (LP1778465).

       Instead the upgrade/FFU ansible tasks now lay down a marker file when
       stopping and disabling the host systemd services. We use this file to
       determine the host nova uid/gid. We then walk the tree and update any
       files that have the host uid/gid to the docker nova uid/gid. As files
       owned by root/qemu etc... are ignored this avoids the issues with open
       filehandles. The marker is removed once the tree has been walked.

       For subsequent runs, or for a new deployment, we simply ensure that the
       docker nova user/group owns all directories. This is required as the
       directories are created with root ownership in host_prep_tasks (the
       docker nova uid/gid is not known in this context). We also change
       permissions of directories and files with a given umask value applied
       (defaults to 027, i.e. results into 0750/0640). As the root/qemu owned
       files retain its owner unchanged, but only permissions, there should be
       no issues with open filehandlers
    """
    def __init__(self, statedir, upgrade_marker='upgrade_marker',
                 nova_user='nova', secontext_marker='../_nova_secontext',
                 exclude_paths=None, umask=None):
        self.statedir = statedir
        self.nova_user = nova_user

        self.upgrade_marker_path = os.path.join(statedir, upgrade_marker)
        self.secontext_marker_path = os.path.normpath(os.path.join(statedir, secontext_marker))
        self.upgrade = os.path.exists(self.upgrade_marker_path)

        self.exclude_paths = [self.upgrade_marker_path]
        if exclude_paths is not None:
            for p in exclude_paths:
                if not p.startswith(os.path.sep):
                    p = os.path.join(self.statedir, p)
                self.exclude_paths.append(p)

        self.target_uid, self.target_gid = self._get_nova_ids()
        self.previous_uid, self.previous_gid = self._get_previous_nova_ids()
        self.id_change = (self.target_uid, self.target_gid) != \
            (self.previous_uid, self.previous_gid)

        self.umask = DEFAULT_UMASK
        if umask:
            try:
                self.umask = oct(int(umask, 8))
                if self.umask not in ALLOWED_UMASK:
                    raise
            except Exception:
                LOG.warn("Unexpected umask %s is not in "
                         "allowed umask %s: using default %s",
                         umask, ALLOWED_UMASK, DEFAULT_UMASK)
                self.umask = DEFAULT_UMASK

        self.target_dir_mode = self._get_umasked_mode('0o777')
        self.target_file_mode = self._get_umasked_mode('0o666')
        if self.target_dir_mode == '0o000':
            self.target_dir_mode = DEFAULT_DIR_MODE
        if self.target_file_mode == '0o000':
            self.target_file_mode = DEFAULT_FILE_MODE

        self.target_secontext = self._get_secontext()

    def _get_nova_ids(self):
        nova_uid, nova_gid = pwd.getpwnam(self.nova_user)[2:4]
        return nova_uid, nova_gid

    def _get_previous_nova_ids(self):
        if self.upgrade:
            statinfo = os.stat(self.upgrade_marker_path)
            return statinfo.st_uid, statinfo.st_gid
        else:
            return self._get_nova_ids()

    def _get_secontext(self):
        if os.path.exists(self.secontext_marker_path):
            return selinux.lgetfilecon(self.secontext_marker_path)[1]
        else:
            return None

    def _get_umasked_mode(self, pattern):
        try:
            result = oct(int(pattern, 8) - int(self.umask, 8))
        except Exception:
            LOG.warn("Failed to apply umask %s for permissions %s",
                     self.umask, pattern)
            result = '0o000'
        return result

    def _walk(self, top, chcon=True):
        for f in os.listdir(top):
            pathname = os.path.join(top, f)

            if pathname in self.exclude_paths:
                continue

            try:
                pathinfo = PathManager(pathname)
                LOG.info("Checking %s", pathinfo)
                if pathinfo.is_dir:
                    # Always chown and chmod the directories
                    pathinfo.chown(self.target_uid, self.target_gid)
                    pathinfo.chmod(self.target_dir_mode)
                    chcon_r = chcon
                    if chcon:
                        chcon_r = pathinfo.chcon(self.target_secontext)
                    self._walk(pathname, chcon_r)
                elif self.id_change:
                    # Only chown/chmod files if it's an upgrade and the file is
                    # owned by the host nova uid/gid
                    pathinfo.chown(
                        self.target_uid if pathinfo.uid == self.previous_uid
                        else pathinfo.uid,
                        self.target_gid if pathinfo.gid == self.previous_gid
                        else pathinfo.gid
                    )
                    if chcon:
                        pathinfo.chcon(self.target_secontext)
                    # Always chmod files
                    pathinfo.chmod(self.target_file_mode)
            except Exception:
                # Likely to have been caused by external systems
                # interacting with this directory tree,
                # especially on NFS e.g snapshot dirs.
                # Just ignore it and continue on to the next entry
                continue

    def run(self):
        LOG.info('Applying nova statedir ownership')
        LOG.info('Target ownership for %s: %d:%d, mode: %s',
                 self.statedir,
                 self.target_uid,
                 self.target_gid,
                 self.target_dir_mode)

        pathinfo = PathManager(self.statedir)
        LOG.info("Checking %s", pathinfo)
        pathinfo.chown(self.target_uid, self.target_gid)
        pathinfo.chmod(self.target_dir_mode)
        chcon = self.target_secontext is not None

        if chcon:
            pathinfo.chcon(self.target_secontext)

        self._walk(self.statedir, chcon)

        if self.upgrade:
            LOG.info('Removing upgrade_marker %s',
                     self.upgrade_marker_path)
            os.unlink(self.upgrade_marker_path)

        LOG.info('Nova statedir ownership complete')


def get_exclude_paths():
    exclude_paths = os.environ.get('NOVA_STATEDIR_OWNERSHIP_SKIP')
    if exclude_paths is not None:
        exclude_paths = exclude_paths.split(os.pathsep)
    return exclude_paths


if __name__ == '__main__':
    NovaStatedirOwnershipManager('/var/lib/nova', exclude_paths=get_exclude_paths()).run()
