/******************************************************************************
 *
 *  Copyright 2017 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#include "osi/include/config.h"
#include "osi/include/allocator.h"

#include <base/logging.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <type_traits>

// Empty definition; this type is aliased to list_node_t.
struct config_section_iter_t {};

static bool config_parse(FILE* fp, config_t* config);

template <typename T,
          class = typename std::enable_if<std::is_same<
              config_t, typename std::remove_const<T>::type>::value>>
static auto section_find(T& config, const std::string& section) {
  return std::find_if(
      config.sections.begin(), config.sections.end(),
      [&section](const section_t& sec) { return sec.name == section; });
}

static const entry_t* entry_find(const config_t& config,
                                 const std::string& section,
                                 const std::string& key) {
  auto sec = section_find(config, section);
  if (sec == config.sections.end()) return nullptr;

  for (const entry_t& entry : sec->entries) {
    if (entry.key == key) return &entry;
  }

  return nullptr;
}

std::unique_ptr<config_t> config_new_empty(void) {
  return std::make_unique<config_t>();
}

std::unique_ptr<config_t> config_new(const char* filename) {
  CHECK(filename != nullptr);

  std::unique_ptr<config_t> config = config_new_empty();

  FILE* fp = fopen(filename, "rt");
  if (!fp) {
    LOG(ERROR) << __func__ << ": unable to open file '" << filename
               << "': " << strerror(errno);
    return nullptr;
  }

  if (!config_parse(fp, config.get())) {
    config.reset();
  }

  fclose(fp);
  return config;
}

std::unique_ptr<config_t> config_new_clone(const config_t& src) {
  std::unique_ptr<config_t> ret = config_new_empty();

  for (const section_t& sec : src.sections) {
    for (const entry_t& entry : sec.entries) {
      config_set_string(ret.get(), sec.name, entry.key, entry.value);
    }
  }

  return ret;
}

bool config_has_section(const config_t& config, const std::string& section) {
  return (section_find(config, section) != config.sections.end());
}

bool config_has_key(const config_t& config, const std::string& section,
                    const std::string& key) {
  return (entry_find(config, section, key) != nullptr);
}

int config_get_int(const config_t& config, const std::string& section,
                   const std::string& key, int def_value) {
  const entry_t* entry = entry_find(config, section, key);
  if (!entry) return def_value;

  size_t endptr;
  int ret = stoi(entry->value, &endptr);
  return (endptr == entry->value.size()) ? ret : def_value;
}

bool config_get_bool(const config_t& config, const std::string& section,
                     const std::string& key, bool def_value) {
  const entry_t* entry = entry_find(config, section, key);
  if (!entry) return def_value;

  if (entry->value == "true") return true;
  if (entry->value == "false") return false;

  return def_value;
}

const std::string* config_get_string(const config_t& config,
                                     const std::string& section,
                                     const std::string& key,
                                     const std::string* def_value) {
  const entry_t* entry = entry_find(config, section, key);
  if (!entry) return def_value;

  return &entry->value;
}

void config_set_int(config_t* config, const std::string& section,
                    const std::string& key, int value) {
  config_set_string(config, section, key, std::to_string(value));
}

void config_set_bool(config_t* config, const std::string& section,
                     const std::string& key, bool value) {
  config_set_string(config, section, key, value ? "true" : "false");
}

void config_set_string(config_t* config, const std::string& section,
                       const std::string& key, const std::string& value) {
  CHECK(config);

  auto sec = section_find(*config, section);
  if (sec == config->sections.end()) {
    config->sections.emplace_back(section_t{.name = section});
    sec = std::prev(config->sections.end());
  }

  for (entry_t& entry : sec->entries) {
    if (entry.key == key) {
      entry.value = value;
      return;
    }
  }

  sec->entries.emplace_back(entry_t{.key = key, .value = value});
}

bool config_remove_section(config_t* config, const std::string& section) {
  CHECK(config);

  auto sec = section_find(*config, section);
  if (sec == config->sections.end()) return false;

  config->sections.erase(sec);
  return true;
}

bool config_remove_key(config_t* config, const std::string& section,
                       const std::string& key) {
  CHECK(config);
  auto sec = section_find(*config, section);
  if (sec == config->sections.end()) return false;

  for (auto entry = sec->entries.begin(); entry != sec->entries.end();
       ++entry) {
    if (entry->key == key) {
      sec->entries.erase(entry);
      return true;
    }
  }

  return false;
}

bool config_save(const config_t& config, const char* filename) {
  CHECK(filename != nullptr);
  CHECK(*filename != '\0');

  // Steps to ensure content of config file gets to disk:
  //
  // 1) Open and write to temp file (e.g. bt_config.conf.new).
  // 2) Sync the temp file to disk with fsync().
  // 3) Rename temp file to actual config file (e.g. bt_config.conf).
  //    This ensures atomic update.
  // 4) Sync directory that has the conf file with fsync().
  //    This ensures directory entries are up-to-date.
  int dir_fd = -1;
  FILE* fp = nullptr;

  // Build temp config file based on config file (e.g. bt_config.conf.new).
  static const char* temp_file_ext = ".new";
  const int filename_len = strlen(filename);
  const int temp_filename_len = filename_len + strlen(temp_file_ext) + 1;
  char* temp_filename = static_cast<char*>(osi_calloc(temp_filename_len));
  snprintf(temp_filename, temp_filename_len, "%s%s", filename, temp_file_ext);

  // Extract directory from file path (e.g. /data/misc/bluedroid).
  char* temp_dirname = osi_strdup(filename);
  const char* directoryname = dirname(temp_dirname);
  if (!directoryname) {
    LOG(ERROR) << __func__ << ": error extracting directory from '" << filename
               << "': " << strerror(errno);
    goto error;
  }

  dir_fd = open(directoryname, O_RDONLY);
  if (dir_fd < 0) {
    LOG(ERROR) << __func__ << ": unable to open dir '" << directoryname
               << "': " << strerror(errno);
    goto error;
  }

  fp = fopen(temp_filename, "wt");
  if (!fp) {
    LOG(ERROR) << __func__ << ": unable to write to file '" << temp_filename
               << "': " << strerror(errno);
    goto error;
  }

  for (const section_t& section : config.sections) {
    if (fprintf(fp, "[%s]\n", section.name.c_str()) < 0) {
      LOG(ERROR) << __func__ << ": unable to write to file '" << temp_filename
                 << "': " << strerror(errno);
      goto error;
    }

    for (const entry_t& entry : section.entries) {
      if (fprintf(fp, "%s = %s\n", entry.key.c_str(), entry.value.c_str()) <
          0) {
        LOG(ERROR) << __func__ << ": unable to write to file '" << temp_filename
                   << "': " << strerror(errno);
        goto error;
      }
    }

    if (fputc('\n', fp) == EOF) {
      LOG(ERROR) << __func__ << ": unable to write to file '" << temp_filename
                 << "': " << strerror(errno);
      goto error;
    }
  }

  // Sync written temp file out to disk. fsync() is blocking until data makes it
  // to disk.
  if (fsync(fileno(fp)) < 0) {
    LOG(WARNING) << __func__ << ": unable to fsync file '" << temp_filename
                 << "': " << strerror(errno);
  }

  if (fclose(fp) == EOF) {
    LOG(ERROR) << __func__ << ": unable to close file '" << temp_filename
               << "': " << strerror(errno);
    goto error;
  }
  fp = nullptr;

  // Change the file's permissions to Read/Write by User and Group
  if (chmod(temp_filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) == -1) {
    LOG(ERROR) << __func__ << ": unable to change file permissions '"
               << filename << "': " << strerror(errno);
    goto error;
  }

  // Rename written temp file to the actual config file.
  if (rename(temp_filename, filename) == -1) {
    LOG(ERROR) << __func__ << ": unable to commit file '" << filename
               << "': " << strerror(errno);
    goto error;
  }

  // This should ensure the directory is updated as well.
  if (fsync(dir_fd) < 0) {
    LOG(WARNING) << __func__ << ": unable to fsync dir '" << directoryname
                 << "': " << strerror(errno);
  }

  if (close(dir_fd) < 0) {
    LOG(ERROR) << __func__ << ": unable to close dir '" << directoryname
               << "': " << strerror(errno);
    goto error;
  }

  osi_free(temp_filename);
  osi_free(temp_dirname);
  return true;

error:
  // This indicates there is a write issue.  Unlink as partial data is not
  // acceptable.
  unlink(temp_filename);
  if (fp) fclose(fp);
  if (dir_fd != -1) close(dir_fd);
  osi_free(temp_filename);
  osi_free(temp_dirname);
  return false;
}

static char* trim(char* str) {
  while (isspace(*str)) ++str;

  if (!*str) return str;

  char* end_str = str + strlen(str) - 1;
  while (end_str > str && isspace(*end_str)) --end_str;

  end_str[1] = '\0';
  return str;
}

static bool config_parse(FILE* fp, config_t* config) {
  CHECK(fp != nullptr);
  CHECK(config != nullptr);

  int line_num = 0;
  char line[1024];
  char section[1024];
  strcpy(section, CONFIG_DEFAULT_SECTION);

  while (fgets(line, sizeof(line), fp)) {
    char* line_ptr = trim(line);
    ++line_num;

    // Skip blank and comment lines.
    if (*line_ptr == '\0' || *line_ptr == '#') continue;

    if (*line_ptr == '[') {
      size_t len = strlen(line_ptr);
      if (line_ptr[len - 1] != ']') {
        VLOG(1) << __func__ << ": unterminated section name on line "
                << line_num;
        return false;
      }
      strncpy(section, line_ptr + 1, len - 2);  // NOLINT (len < 1024)
      section[len - 2] = '\0';
    } else {
      char* split = strchr(line_ptr, '=');
      if (!split) {
        VLOG(1) << __func__ << ": no key/value separator found on line "
                << line_num;
        return false;
      }

      *split = '\0';
      config_set_string(config, section, trim(line_ptr), trim(split + 1));
    }
  }
  return true;
}
