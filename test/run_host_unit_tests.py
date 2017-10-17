#!/usr/bin/env python
#
# Copyright 2017, The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import sys
import subprocess
import os
import argparse
import multiprocessing

# Registered host based unit tests
# Must have 'host_supported: true'
HOST_TESTS = [
    'bluetoothtbd_test',
    'net_test_btcore',
    'net_test_types',
]


def str2bool(argument, default=False):
  """ Convert a string to a booleen value. """
  argument = str(argument)
  if argument.lower() in ['0', 'f', 'false', 'off', 'no', 'n']:
    return False
  elif argument.lower() in ['1', 't', 'true', 'on', 'yes', 'y']:
    return True
  return default


def check_dir_exists(dir, dirname):
  if not os.path.isdir(dir):
    print "Couldn't find %s (%s)!" % (dirname, dir)
    sys.exit(0)


def get_android_lunch_target_or_die():
  target_product = os.environ.get('TARGET_PRODUCT')
  if not target_product:
    print 'TARGET_PRODUCT not defined: run envsetup.sh / lunch'
    sys.exit(0)
  build_variant = os.environ.get('TARGET_BUILD_VARIANT')
  if not build_variant:
    print 'TARGET_BUILD_VARIANT not defined: run envsetup.sh / lunch'
    sys.exit(0)
  return '-'.join((target_product, build_variant))


def get_android_root_or_die():
  value = os.environ.get('ANDROID_BUILD_TOP')
  if not value:
    print 'ANDROID_BUILD_TOP not defined: run envsetup.sh / lunch'
    sys.exit(0)
  check_dir_exists(value, '$ANDROID_BUILD_TOP')
  return value


def get_android_host_out_or_die():
  value = os.environ.get('ANDROID_HOST_OUT')
  if not value:
    print 'ANDROID_HOST_OUT not defined: run envsetup.sh / lunch'
    sys.exit(0)
  check_dir_exists(value, '$ANDROID_HOST_OUT')
  return value


def get_android_dist_dir_or_die():
  # Check if $DIST_DIR is predefined as environment variable
  value = os.environ.get('DIST_DIR')
  if not value:
    # If not use the default path
    ANDROID_BUILD_TOP = get_android_root_or_die()
    value = os.path.join(os.path.join(ANDROID_BUILD_TOP, 'out'), 'dist')
  if not os.path.isdir(value):
    if os.path.exists(value):
      print '%s is not a directory!' % (value)
      sys.exit(0)
    os.makedirs(value)
  return value


def get_native_test_root_or_die():
  android_host_out = get_android_host_out_or_die()
  test_root = os.path.join(android_host_out, 'nativetest64')
  if not os.path.isdir(test_root):
    test_root = os.path.join(android_host_out, 'nativetest')
    if not os.path.isdir(test_root):
      print 'Neither nativetest64 nor nativetest directory exist,' \
        ' please compile first'
      sys.exit(0)
  return test_root


def get_test_cmd_or_die(test_root, test_name, enable_xml, test_filter):
  test_path = os.path.join(os.path.join(test_root, test_name), test_name)
  if not os.path.isfile(test_path):
    print 'Cannot find: ' + test_path
    test_results.append(False)
    return None
  cmd = [test_path]
  if enable_xml:
    dist_dir = get_android_dist_dir_or_die()
    cmd.append('--gtest_output=xml:gtest/%s_test_details.xml' % test_name)
  if test_filter:
    cmd.append('--gtest_filter=%s' % test_filter)
  return cmd


# path is relative to Android build top
def build_all_targets_in_dir(path, num_tasks):
  ANDROID_LUNCH_TARGET = get_android_lunch_target_or_die()
  ANDROID_BUILD_TOP = get_android_root_or_die()
  combined_path = os.path.join(ANDROID_BUILD_TOP, path)
  if not os.path.isdir(combined_path):
    print 'Combined path not found: ' + combined_path
    sys.exit(0)
  build_cmd = ['mmma']
  if num_tasks > 1:
    build_cmd.append('-j' + str(num_tasks))
  build_cmd.append(path)
  bash_cmd = ('cd {android_home} '
              '&& source build/envsetup.sh '
              '&& lunch {product_combo} '
              '&& {build_cmd}'.format(
                  android_home=ANDROID_BUILD_TOP,
                  product_combo=ANDROID_LUNCH_TARGET,
                  build_cmd=' '.join(build_cmd)))
  p = subprocess.Popen(
      bash_cmd, cwd=ANDROID_BUILD_TOP, env=os.environ, shell=True)
  if p.wait() != 0:
    print 'BUILD FAILED'
    sys.exit(0)
  return


def main():
  """ run_host_unit_tests.py - Run registered host based unit tests
  """
  parser = argparse.ArgumentParser(description='Run host based unit tests.')
  parser.add_argument(
      '--enable_xml',
      type=str2bool,
      dest='enable_xml',
      nargs='?',
      const=True,
      default=False,
      help=
      'Whether to output structured XML log output in out/dist/gtest directory')
  parser.add_argument(
      '-j',
      type=int,
      nargs='?',
      dest='num_tasks',
      const=-1,
      default=-1,
      help='Number of tasks to run at the same time')
  parser.add_argument(
      'rest',
      nargs=argparse.REMAINDER,
      help='-- args, other gtest arguments for each individual test')
  args = parser.parse_args()

  build_all_targets_in_dir('system/bt', args.num_tasks)
  TEST_ROOT = get_native_test_root_or_die()
  test_results = []
  for test in HOST_TESTS:
    test_cmd = get_test_cmd_or_die(TEST_ROOT, test, args.enable_xml, args.rest)
    if not test_cmd:
      continue
    if subprocess.call(test_cmd) != 0:
      test_results.append(False)
    else:
      test_results.append(True)
  if not all(test_results):
    failures = [i for i, x in enumerate(test_results) if not x]
    for index in failures:
      print 'TEST FAILLED: ' + HOST_TESTS[index]
    sys.exit(0)
  print 'TEST PASSED ' + str(len(test_results)) + ' tests were run'
  sys.exit(0)


if __name__ == '__main__':
  main()
