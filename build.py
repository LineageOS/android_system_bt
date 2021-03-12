#!/usr/bin/env python3

#  Copyright 2021 Google, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at:
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
""" Build BT targets on the host system.

For building, you will first have to stage a platform directory that has the
following structure:
|-common-mk
|-bt
|-external
|-|-rust
|-|-|-vendor

The simplest way to do this is to check out platform2 to another directory (that
is not a subdir of this bt directory), symlink bt there and symlink the rust
vendor repository as well.
"""
import argparse
import multiprocessing
import os
import shutil
import six
import subprocess
import sys

# Use flags required by common-mk (find -type f | grep -nE 'use[.]' {})
COMMON_MK_USES = [
    'asan',
    'coverage',
    'cros_host',
    'fuzzer',
    'fuzzer',
    'msan',
    'profiling',
    'tcmalloc',
    'test',
    'ubsan',
]

# Default use flags.
USE_DEFAULTS = {
    'android': False,
    'bt_nonstandard_codecs': False,
    'test': False,
}

VALID_TARGETS = [
    'prepare',  # Prepare the output directory (gn gen + rust setup)
    'tools',  # Build the host tools (i.e. packetgen)
    'rust',  # Build only the rust components + copy artifacts to output dir
    'main',  # Build the main C++ codebase
    'test',  # Build and run the unit tests
    'clean',  # Clean up output directory
    'all',  # All targets except test and clean
]


class UseFlags():

    def __init__(self, use_flags):
        """ Construct the use flags.

        Args:
            use_flags: List of use flags parsed from the command.
        """
        self.flags = {}

        # Import use flags required by common-mk
        for use in COMMON_MK_USES:
            self.set_flag(use, False)

        # Set our defaults
        for use, value in USE_DEFAULTS.items():
            self.set_flag(use, value)

        # Set use flags - value is set to True unless the use starts with -
        # All given use flags always override the defaults
        for use in use_flags:
            value = not use.startswith('-')
            self.set_flag(use, value)

    def set_flag(self, key, value=True):
        setattr(self, key, value)
        self.flags[key] = value


class HostBuild():

    def __init__(self, args):
        """ Construct the builder.

        Args:
            args: Parsed arguments from ArgumentParser
        """
        self.args = args

        # Set jobs to number of cpus unless explicitly set
        self.jobs = self.args.jobs
        if not self.jobs:
            self.jobs = multiprocessing.cpu_count()

        # Normalize all directories
        self.output_dir = os.path.abspath(self.args.output)
        self.platform_dir = os.path.abspath(self.args.platform_dir)
        self.sysroot = self.args.sysroot
        self.use_board = os.path.abspath(self.args.use_board) if self.args.use_board else None
        self.libdir = self.args.libdir

        # If default target isn't set, build everything
        self.target = 'all'
        if hasattr(self.args, 'target') and self.args.target:
            self.target = self.args.target

        self.use = UseFlags(self.args.use if self.args.use else [])

        # Validate platform directory
        assert os.path.isdir(self.platform_dir), 'Platform dir does not exist'
        assert os.path.isfile(os.path.join(self.platform_dir, '.gn')), 'Platform dir does not have .gn at root'

        # Make sure output directory exists (or create it)
        os.makedirs(self.output_dir, exist_ok=True)

        # Set some default attributes
        self.libbase_ver = None

        self.configure_environ()

    def configure_environ(self):
        """ Configure environment variables for GN and Cargo.
        """
        self.env = os.environ.copy()

        # Make sure cargo home dir exists and has a bin directory
        cargo_home = os.path.join(self.output_dir, 'cargo_home')
        os.makedirs(cargo_home, exist_ok=True)
        os.makedirs(os.path.join(cargo_home, 'bin'), exist_ok=True)

        # Configure Rust env variables
        self.env['CARGO_TARGET_DIR'] = self.output_dir
        self.env['CARGO_HOME'] = os.path.join(self.output_dir, 'cargo_home')

        # Configure some GN variables
        if self.use_board:
            self.env['PKG_CONFIG_PATH'] = os.path.join(self.use_board, self.libdir, 'pkgconfig')
            libdir = os.path.join(self.use_board, self.libdir)
            if self.env.get('LIBRARY_PATH'):
                libpath = self.env['LIBRARY_PATH']
                self.env['LIBRARY_PATH'] = '{}:{}'.format(libdir, libpath)
            else:
                self.env['LIBRARY_PATH'] = libdir

    def run_command(self, target, args, cwd=None, env=None):
        """ Run command and stream the output.
        """
        # Set some defaults
        if not cwd:
            cwd = self.platform_dir
        if not env:
            env = self.env

        log_file = os.path.join(self.output_dir, '{}.log'.format(target))
        with open(log_file, 'wb') as lf:
            rc = 0
            process = subprocess.Popen(args, cwd=cwd, env=env, stdout=subprocess.PIPE)
            while True:
                line = process.stdout.readline()
                print(line.decode('utf-8'), end="")
                lf.write(line)
                if not line:
                    rc = process.poll()
                    if rc is not None:
                        break

                    time.sleep(0.1)

            if rc != 0:
                raise Exception("Return code is {}".format(rc))

    def _get_basever(self):
        if self.libbase_ver:
            return self.libbase_ver

        self.libbase_ver = os.environ.get('BASE_VER', '')
        if not self.libbase_ver:
            base_file = os.path.join(self.sysroot, 'usr/share/libchrome/BASE_VER')
            try:
                with open(base_file, 'r') as f:
                    self.libbase_ver = f.read().strip('\n')
            except:
                self.libbase_ver = 'NOT-INSTALLED'

        return self.libbase_ver

    def _gn_default_output(self):
        return os.path.join(self.output_dir, 'out/Default')

    def _gn_configure(self):
        """ Configure all required parameters for platform2.

        Mostly copied from //common-mk/platform2.py
        """
        clang = self.args.clang

        def to_gn_string(s):
            return '"%s"' % s.replace('"', '\\"')

        def to_gn_list(strs):
            return '[%s]' % ','.join([to_gn_string(s) for s in strs])

        def to_gn_args_args(gn_args):
            for k, v in gn_args.items():
                if isinstance(v, bool):
                    v = str(v).lower()
                elif isinstance(v, list):
                    v = to_gn_list(v)
                elif isinstance(v, six.string_types):
                    v = to_gn_string(v)
                else:
                    raise AssertionError('Unexpected %s, %r=%r' % (type(v), k, v))
                yield '%s=%s' % (k.replace('-', '_'), v)

        gn_args = {
            'platform_subdir': 'bt',
            'cc': 'clang' if clang else 'gcc',
            'cxx': 'clang++' if clang else 'g++',
            'ar': 'llvm-ar' if clang else 'ar',
            'pkg-config': 'pkg-config',
            'clang_cc': clang,
            'clang_cxx': clang,
            'OS': 'linux',
            'sysroot': self.sysroot,
            'libdir': os.path.join(self.sysroot, self.libdir),
            'build_root': self.output_dir,
            'platform2_root': self.platform_dir,
            'libbase_ver': self._get_basever(),
            'enable_exceptions': os.environ.get('CXXEXCEPTIONS', 0) == '1',
            'external_cflags': [],
            'external_cxxflags': [],
            'enable_werror': False,
        }

        if clang:
            # Make sure to mark the clang use flag as true
            self.use.set_flag('clang', True)
            gn_args['external_cxxflags'] += ['-I/usr/include/']

        # EXTREME HACK ALERT
        #
        # In my laziness, I am supporting building against an already built
        # sysroot path (i.e. chromeos board) so that I don't have to build
        # libchrome or modp_b64 locally.
        if self.use_board:
            includedir = os.path.join(self.use_board, 'usr/include')
            gn_args['external_cxxflags'] += [
                '-I{}'.format(includedir),
                '-I{}/libchrome'.format(includedir),
                '-I{}/gtest'.format(includedir),
                '-I{}/gmock'.format(includedir),
                '-I{}/modp_b64'.format(includedir),
            ]
        gn_args_args = list(to_gn_args_args(gn_args))
        use_args = ['%s=%s' % (k, str(v).lower()) for k, v in self.use.flags.items()]
        gn_args_args += ['use={%s}' % (' '.join(use_args))]

        gn_args = [
            'gn',
            'gen',
        ]

        if self.args.verbose:
            gn_args.append('-v')

        gn_args += [
            '--root=%s' % self.platform_dir,
            '--args=%s' % ' '.join(gn_args_args),
            self._gn_default_output(),
        ]

        print('DEBUG: PKG_CONFIG_PATH is', self.env['PKG_CONFIG_PATH'])

        self.run_command('configure', gn_args)

    def _gn_build(self, target):
        """ Generate the ninja command for the target and run it.
        """
        args = ['%s:%s' % ('bt', target)]
        ninja_args = ['ninja', '-C', self._gn_default_output()]
        if self.jobs:
            ninja_args += ['-j', str(self.jobs)]
        ninja_args += args

        if self.args.verbose:
            ninja_args.append('-v')

        self.run_command('build', ninja_args)

    def _rust_configure(self):
        """ Generate config file at cargo_home so we use vendored crates.
        """
        template = """
        [source.systembt]
        directory = "{}/external/rust/vendor"

        [source.crates-io]
        replace-with = "systembt"
        local-registry = "/nonexistent"
        """
        contents = template.format(self.platform_dir)
        with open(os.path.join(self.env['CARGO_HOME'], 'config'), 'w') as f:
            f.write(contents)

    def _rust_build(self):
        """ Run `cargo build` from platform2/bt directory.
        """
        self.run_command('rust', ['cargo', 'build'], cwd=os.path.join(self.platform_dir, 'bt'), env=self.env)

    def _target_prepare(self):
        """ Target to prepare the output directory for building.

        This runs gn gen to generate all rquired files and set up the Rust
        config properly. This will be run
        """
        self._gn_configure()
        self._rust_configure()

    def _target_tools(self):
        """ Build the tools target in an already prepared environment.
        """
        self._gn_build('tools')

        # Also copy bluetooth_packetgen to CARGO_HOME so it's available
        shutil.copy(
            os.path.join(self._gn_default_output(), 'bluetooth_packetgen'), os.path.join(self.env['CARGO_HOME'], 'bin'))

    def _target_rust(self):
        """ Build rust artifacts in an already prepared environment.
        """
        self._rust_build()

    def _target_main(self):
        """ Build the main GN artifacts in an already prepared environment.
        """
        self._gn_build('all')

    def _target_test(self):
        """ Runs the host tests.
        """
        raise Exception('Not yet implemented')

    def _target_clean(self):
        """ Delete the output directory entirely.
        """
        shutil.rmtree(self.output_dir)

    def _target_all(self):
        """ Build all common targets (skipping test and clean).
        """
        self._target_prepare()
        self._target_tools()
        self._target_rust()
        self._target_main()

    def build(self):
        """ Builds according to self.target
        """
        print('Building target ', self.target)

        if self.target == 'prepare':
            self._target_prepare()
        elif self.target == 'tools':
            self._target_tools()
        elif self.target == 'rust':
            self._target_rust()
        elif self.target == 'main':
            self._target_main()
        elif self.target == 'test':
            self.use.set_flag('test')
            self._target_all()
            self._target_test()
        elif self.target == 'clean':
            self._target_clean()
        elif self.target == 'all':
            self._target_all()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple build for host.')
    parser.add_argument('--output', help='Output directory for the build.', required=True)
    parser.add_argument('--platform-dir', help='Directory where platform2 is staged.', required=True)
    parser.add_argument('--clang', help='Use clang compiler.', default=False, action="store_true")
    parser.add_argument('--use', help='Set a specific use flag.')
    parser.add_argument('--target', help='Run specific build target')
    parser.add_argument('--sysroot', help='Set a specific sysroot path', default='/')
    parser.add_argument('--libdir', help='Libdir - default = usr/lib64', default='usr/lib64')
    parser.add_argument('--use-board', help='Use a built x86 board for dependencies. Provide path.')
    parser.add_argument('--jobs', help='Number of jobs to run', default=0, type=int)
    parser.add_argument('--verbose', help='Verbose logs for build.')

    args = parser.parse_args()
    build = HostBuild(args)
    build.build()
