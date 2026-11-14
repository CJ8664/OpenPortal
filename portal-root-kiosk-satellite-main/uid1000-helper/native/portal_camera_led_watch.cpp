#include <android/log.h>
#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

namespace {

#ifndef PORTAL_UID1000_DATA_DIRECTORY
#define PORTAL_UID1000_DATA_DIRECTORY "/data/portal-uid1000"
#endif

constexpr char kTag[] = "PortalCameraLed";
constexpr char kPresenceTag[] = "PortalPresence";
constexpr char kCameraEnabled[] =
    PORTAL_UID1000_DATA_DIRECTORY "/camera-led-enabled";
constexpr char kPresenceFps[] =
    PORTAL_UID1000_DATA_DIRECTORY "/presence-fps";
constexpr char kWirelessAdbEnabled[] =
    PORTAL_UID1000_DATA_DIRECTORY "/wireless-adb-enabled";
constexpr char kAdbFrameworkEnabled[] =
    PORTAL_UID1000_DATA_DIRECTORY "/adb-framework-enabled";
constexpr char kSystemThemeControlEnabled[] =
    PORTAL_UID1000_DATA_DIRECTORY "/system-theme-control-enabled";
// Android's debug_prop is writable by UID 2000 and non-persistent. The
// root-owned marker above is the durable capability gate.
constexpr char kSystemThemeProperty[] = "debug.portal.system_theme";
constexpr char kSystemThemeTag[] = "PortalSystemTheme";
constexpr char kAdbFrameworkTag[] = "PortalAdbFramework";
constexpr char kPermissionGrantsConfig[] =
    "/data/data/com.facebook.alohasdk.virtualcameramanager/"
    "permission-grants.txt";
constexpr char kPermissionGrantsTag[] = "PortalPermissionGrants";
constexpr char kPackagesXml[] = "/data/system/packages.xml";
constexpr char kPackagesXmlTmp[] = "/data/system/packages.xml.portal-tmp";
constexpr char kPackagesXmlBackup[] = "/data/system/packages.xml.portal-bak";
constexpr char kPackagesXmlBackupTmp[] =
    "/data/system/packages.xml.portal-bak.tmp";
// PMS maintains this sibling and preferentially reads it on boot (deleting
// the primary) if it exists, so a stale copy can mask our edited primary.
constexpr char kPackagesXmlSystemBackup[] = "/data/system/packages-backup.xml";
// The host priv-app (VirtualCameraManagerService) runs as android.uid.system,
// so its own data dir is system_app_data_file and is writable by this helper.
constexpr char kPortalHostDataDir[] =
    "/data/data/com.facebook.alohasdk.virtualcameramanager";
constexpr char kPortalDryrunMarker[] =
    "/data/data/com.facebook.alohasdk.virtualcameramanager/portal-dryrun";
constexpr char kPortalRestoreMarker[] =
    "/data/data/com.facebook.alohasdk.virtualcameramanager/portal-restore-marker";
constexpr char kClientLibrary[] =
    "/system/lib64/privacystate_client1.0.so";
constexpr char kConstructor[] =
    "_ZN8facebook5aloha18PrivacyStateClientC1EN6vendor8facebook8hardware"
    "12privacystate4V1_09ComponentEjb";
constexpr char kDestructor[] =
    "_ZN8facebook5aloha18PrivacyStateClientD1Ev";
constexpr char kConnect[] =
    "_ZN8facebook5aloha18PrivacyStateClient11connectIntfEv";
constexpr char kDisconnect[] =
    "_ZN8facebook5aloha18PrivacyStateClient14disconnectIntfEv";
constexpr char kClear[] =
    "_ZN8facebook5aloha18PrivacyStateClient8clearLedEv";
constexpr char kGet[] =
    "_ZN8facebook5aloha18PrivacyStateClient6getLedEv";

using Constructor = void (*)(void *, uint8_t, uint32_t, bool);
using Destructor = void (*)(void *);
using ConnectMethod = int (*)(void *);
using BoolMethod = bool (*)(void *);
using VoidMethod = void (*)(void *);

volatile sig_atomic_t running = 1;
volatile sig_atomic_t stop_signal = 0;

using LogVPrint = int (*)(int, const char *, const char *, va_list);
LogVPrint real_log_vprint = nullptr;

int quiet_privacy_log(int priority, const char *tag, const char *format, ...) {
  if (tag != nullptr && strcmp(tag, "PrivacyStateClient") == 0) return 0;
  if (real_log_vprint == nullptr) return 0;
  va_list arguments;
  va_start(arguments, format);
  int result = real_log_vprint(priority, tag, format, arguments);
  va_end(arguments);
  return result;
}

uintptr_t loaded_address(uintptr_t base, uintptr_t value) {
  return value >= base ? value : base + value;
}

int silence_privacy_client_logs(dl_phdr_info *info, size_t, void *) {
  if (info->dlpi_name == nullptr ||
      strstr(info->dlpi_name, "privacystate_client1.0.so") == nullptr) {
    return 0;
  }

  const ElfW(Dyn) *dynamic = nullptr;
  for (ElfW(Half) index = 0; index < info->dlpi_phnum; ++index) {
    if (info->dlpi_phdr[index].p_type == PT_DYNAMIC) {
      dynamic = reinterpret_cast<const ElfW(Dyn) *>(
          info->dlpi_addr + info->dlpi_phdr[index].p_vaddr);
      break;
    }
  }
  if (dynamic == nullptr) return 1;

  const ElfW(Rela) *relocations = nullptr;
  size_t relocation_size = 0;
  const ElfW(Sym) *symbols = nullptr;
  const char *strings = nullptr;
  for (const ElfW(Dyn) *entry = dynamic; entry->d_tag != DT_NULL; ++entry) {
    switch (entry->d_tag) {
      case DT_JMPREL:
        relocations = reinterpret_cast<const ElfW(Rela) *>(loaded_address(
            info->dlpi_addr, static_cast<uintptr_t>(entry->d_un.d_ptr)));
        break;
      case DT_PLTRELSZ:
        relocation_size = static_cast<size_t>(entry->d_un.d_val);
        break;
      case DT_SYMTAB:
        symbols = reinterpret_cast<const ElfW(Sym) *>(loaded_address(
            info->dlpi_addr, static_cast<uintptr_t>(entry->d_un.d_ptr)));
        break;
      case DT_STRTAB:
        strings = reinterpret_cast<const char *>(loaded_address(
            info->dlpi_addr, static_cast<uintptr_t>(entry->d_un.d_ptr)));
        break;
    }
  }
  if (relocations == nullptr || relocation_size == 0 || symbols == nullptr ||
      strings == nullptr) {
    return 1;
  }

  const long page_size = sysconf(_SC_PAGESIZE);
  const size_t count = relocation_size / sizeof(ElfW(Rela));
  for (size_t index = 0; index < count; ++index) {
    const ElfW(Rela) &relocation = relocations[index];
    size_t symbol_index = ELF64_R_SYM(relocation.r_info);
    const char *name = strings + symbols[symbol_index].st_name;
    if (strcmp(name, "__android_log_print") != 0) continue;
    auto *slot = reinterpret_cast<void **>(
        info->dlpi_addr + relocation.r_offset);
    uintptr_t page = reinterpret_cast<uintptr_t>(slot) &
        ~static_cast<uintptr_t>(page_size - 1);
    if (mprotect(reinterpret_cast<void *>(page), static_cast<size_t>(page_size),
                 PROT_READ | PROT_WRITE) != 0) {
      return 1;
    }
    *slot = reinterpret_cast<void *>(&quiet_privacy_log);
    (void)mprotect(reinterpret_cast<void *>(page),
                   static_cast<size_t>(page_size), PROT_READ);
    return 1;
  }
  return 1;
}

void stop(int signal_number) {
  stop_signal = signal_number;
  running = 0;
}

void *symbol(void *library, const char *name) {
  dlerror();
  void *result = dlsym(library, name);
  const char *error = dlerror();
  if (error != nullptr) {
    __android_log_print(ANDROID_LOG_ERROR, kTag,
                        "missing symbol %s: %s", name, error);
    return nullptr;
  }
  return result;
}

int claim_singleton() {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  constexpr char name[] = "portal.camera.led.watch";
  static_assert(sizeof(name) < sizeof(address.sun_path));
  memcpy(address.sun_path + 1, name, sizeof(name) - 1);
  socklen_t length = static_cast<socklen_t>(
      sizeof(address.sun_family) + 1 + sizeof(name) - 1);
  if (bind(fd, reinterpret_cast<sockaddr *>(&address), length) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

int read_presence_fps() {
  int fd = open(kPresenceFps, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return 0;
  char value[16]{};
  ssize_t count = read(fd, value, sizeof(value) - 1);
  close(fd);
  if (count <= 0) return 0;
  char *end = nullptr;
  long fps = strtol(value, &end, 10);
  while (end != nullptr && (*end == '\n' || *end == '\r' || *end == ' ')) {
    ++end;
  }
  return end != nullptr && *end == '\0' && fps >= 1 && fps <= 10
      ? static_cast<int>(fps) : 0;
}

int run_command(const char *const arguments[]) {
  pid_t child = fork();
  if (child < 0) return -1;
  if (child == 0) {
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd >= 0) {
      dup2(null_fd, STDIN_FILENO);
      dup2(null_fd, STDOUT_FILENO);
      dup2(null_fd, STDERR_FILENO);
      if (null_fd > STDERR_FILENO) close(null_fd);
    }
    execv(arguments[0], const_cast<char *const *>(arguments));
    _exit(127);
  }
  int status = 0;
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) return -1;
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int run_command_capture(const char *const arguments[], char *output,
                        size_t output_size) {
  if (output == nullptr || output_size == 0) return -1;
  output[0] = '\0';
  int descriptors[2];
  if (pipe2(descriptors, O_CLOEXEC) != 0) return -1;
  pid_t child = fork();
  if (child < 0) {
    close(descriptors[0]);
    close(descriptors[1]);
    return -1;
  }
  if (child == 0) {
    close(descriptors[0]);
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd >= 0) {
      dup2(null_fd, STDIN_FILENO);
      dup2(null_fd, STDERR_FILENO);
      if (null_fd > STDERR_FILENO) close(null_fd);
    }
    dup2(descriptors[1], STDOUT_FILENO);
    close(descriptors[1]);
    execv(arguments[0], const_cast<char *const *>(arguments));
    _exit(127);
  }
  close(descriptors[1]);
  size_t used = 0;
  char discard[128];
  for (;;) {
    char *destination = used + 1 < output_size ? output + used : discard;
    size_t available = used + 1 < output_size
        ? output_size - used - 1
        : sizeof(discard);
    ssize_t count = read(descriptors[0], destination, available);
    if (count == 0) break;
    if (count < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (destination != discard) used += static_cast<size_t>(count);
  }
  close(descriptors[0]);
  output[used] = '\0';
  int status = 0;
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) return -1;
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

[[noreturn]] void activate_presence(int fps) {
  sleep(15);
  const char *const start[] = {
      "/system/bin/cmd", "activity", "start", "--user", "0", "-n",
      "com.facebook.portal.aiservice/"
      "com.facebook.alohaapp.app.MainActivity", nullptr};
  int activity_status = run_command(start);
  sleep(3);
  const char *const home[] = {
      "/system/bin/cmd", "activity", "start", "--user", "0", "-a",
      "android.intent.action.MAIN", "-c", "android.intent.category.HOME",
      nullptr};
  int home_status = run_command(home);
  if (activity_status == 0 && home_status == 0) {
    __android_log_print(ANDROID_LOG_INFO, kPresenceTag,
                        "presence FPS activation complete fps=%d uid=%d",
                        fps, getuid());
    _exit(0);
  }
  __android_log_print(ANDROID_LOG_ERROR, kPresenceTag,
                      "presence FPS activation failed fps=%d uid=%d "
                      "activity_status=%d home_status=%d",
                      fps, getuid(), activity_status, home_status);
  _exit(1);
}

[[noreturn]] void activate_wireless_adb() {
  // Meta's omni init rules disable adbd late in boot for production builds.
  // Run after that rule, then keep watching because a failed bugreport can
  // also stop adbd later in the same boot. The provisioner separately
  // persists service.adb.tcp.port=5555.
  sleep(20);
  for (;;) {
    char state[PROP_VALUE_MAX]{};
    bool running =
        __system_property_get("init.svc.adbd", state) > 0 &&
        strcmp(state, "running") == 0;
    if (!running) {
      errno = 0;
      int persist_status =
          __system_property_set("persist.sys.usb.config", "adb");
      int persist_errno = errno;
      errno = 0;
      int none_status = __system_property_set("sys.usb.config", "none");
      int none_errno = errno;
      sleep(1);
      errno = 0;
      int adb_status = __system_property_set("sys.usb.config", "adb");
      int adb_errno = errno;
      __android_log_print(
          adb_status == 0 ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
          kTag,
          "wireless ADB activation uid=%d state=%s persist=%d/%d "
          "none=%d/%d adb=%d/%d",
          getuid(), state[0] ? state : "unset", persist_status,
          persist_errno, none_status, none_errno, adb_status, adb_errno);
    }
    sleep(10);
  }
}

[[noreturn]] void activate_adb_framework() {
  const char *const get_adb_enabled[] = {
      "/system/bin/cmd", "settings", "get", "global", "adb_enabled",
      nullptr};
  const char *const enable_adb_framework[] = {
      "/system/bin/cmd", "settings", "put", "global", "adb_enabled", "1",
      nullptr};
  unsigned int cycles = 0;
  for (;;) {
    // Meta firmware can reset Settings.Global.adb_enabled during boot. Keeping
    // adbd alive is not enough: existing keys still work, but Android cannot
    // show the confirmation dialog for a new host. Check frequently while boot
    // settles, then once per minute, and only write when the value is wrong.
    if (cycles < 12 || cycles % 6 == 0) {
      char adb_enabled[32]{};
      int get_status = run_command_capture(
          get_adb_enabled, adb_enabled, sizeof(adb_enabled));
      char *end = adb_enabled + strlen(adb_enabled);
      while (end > adb_enabled &&
             (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' ' ||
              end[-1] == '\t')) {
        *--end = '\0';
      }
      if (get_status != 0 || strcmp(adb_enabled, "1") != 0) {
        int put_status = run_command(enable_adb_framework);
        __android_log_print(
            put_status == 0 ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
            kAdbFrameworkTag,
            "activation uid=%d previous=%s get_status=%d put_status=%d",
            getuid(), adb_enabled[0] ? adb_enabled : "unavailable",
            get_status, put_status);
      }
    }
    ++cycles;
    sleep(10);
  }
}

enum class SystemTheme {
  kNone,
  kLight,
  kDark,
};

SystemTheme requested_system_theme() {
  char value[PROP_VALUE_MAX]{};
  if (__system_property_get(kSystemThemeProperty, value) <= 0) {
    return SystemTheme::kNone;
  }
  if (strcmp(value, "light") == 0) return SystemTheme::kLight;
  if (strcmp(value, "dark") == 0) return SystemTheme::kDark;
  return SystemTheme::kNone;
}

[[noreturn]] void activate_system_theme_control() {
  SystemTheme applied = SystemTheme::kNone;
  for (;;) {
    SystemTheme requested = requested_system_theme();
    if (requested == SystemTheme::kNone) {
      applied = SystemTheme::kNone;
    } else if (requested != applied) {
      const char *const light[] = {
          "/system/bin/cmd", "uimode", "night", "no", nullptr};
      const char *const dark[] = {
          "/system/bin/cmd", "uimode", "night", "yes", nullptr};
      const char *const *arguments =
          requested == SystemTheme::kDark ? dark : light;
      int status = run_command(arguments);
      __android_log_print(
          status == 0 ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
          kSystemThemeTag,
          "system theme request mode=%s uid=%d status=%d",
          requested == SystemTheme::kDark ? "dark" : "light", getuid(),
          status);
      if (status == 0) applied = requested;
      if (status != 0) sleep(2);
    }
    usleep(250000);
  }
}

bool omni_wireless_adb_requested() {
  char device[PROP_VALUE_MAX]{};
  char port[PROP_VALUE_MAX]{};
  return __system_property_get("ro.product.device", device) > 0 &&
      strcmp(device, "omni") == 0 &&
      __system_property_get("service.adb.tcp.port", port) > 0 &&
      strcmp(port, "5555") == 0;
}

// ---------------------------------------------------------------------------
// Permission-grant re-assertion.
//
// Reads a config file whose lines are "<package> <permission>" whitespace-
// separated (with '#' comments) and ensures each permission is present as a
// granted <item> inside the target package's <perms> block in
// /data/system/packages.xml. This is how a signature|privileged permission
// (which a normal sideload can never otherwise obtain) is granted durably:
// uid 1000 rewrites the Package Manager settings file using the exact XML shape
// Android 9's Settings.java writes, and the helper re-applies it on every boot.
//
// The helper runs in a priv-app's onCreate, AFTER PMS has already read
// packages.xml for this boot, so an edit only takes effect on the NEXT boot.
// PMS does not rewrite packages.xml at shutdown, so a quiet boot leaves the
// edit intact until the next boot reads it. There is therefore NO in-place
// framework restart here: the helper edits the file once per boot and leaves
// the reload to the next full reboot.
//
// Boot sequencing (see RootPlan Steps 4.5 / 5.6):
//   1. recovery marker present  -> restore .portal-bak snapshot, skip edits.
//   2. dry-run marker present   -> no-op write-cycle self-test, no edit; the
//      marker is deleted only if every step succeeds.
//   3. otherwise                -> real, idempotent edit (snapshot captured
//      before the first write), then post-edit self-validation.
// ---------------------------------------------------------------------------

struct GrantRule {
  char package[256];
  char permission[256];
};

// Android package and permission names are dot-separated [A-Za-z0-9_]
// segments. Restricting config input to this charset also means the names
// never contain an XML metacharacter, so interpolating them into the
// <item .../> element below needs no escaping and cannot inject markup.
bool valid_android_name(const char *name) {
  if (name == nullptr || *name == '\0' || strlen(name) >= 256) return false;
  for (const char *p = name; *p != '\0'; ++p) {
    bool alnum = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                 (*p >= '0' && *p <= '9');
    if (!alnum && *p != '.' && *p != '_') return false;
  }
  return true;
}

// Defined below (with the other packages.xml file helpers); reads a whole
// regular file into a fresh NUL-terminated buffer, bounded by `max_size`.
char *read_whole_file(const char *path, size_t max_size, size_t *len_out);

int read_grant_config(GrantRule *rules, int max_rules) {
  constexpr size_t kMaxConfigBytes = 64 * 1024;
  char *buf = read_whole_file(kPermissionGrantsConfig, kMaxConfigBytes,
                              nullptr);
  if (buf == nullptr) {
    // read_whole_file returns nullptr for absent, empty, unreadable, or
    // oversized input. Distinguish the oversized case so the operator gets a
    // specific signal that the config was rejected rather than silently
    // truncated (a truncated final token could still pass valid_android_name
    // and produce a grant item for a non-existent permission).
    struct stat st{};
    if (stat(kPermissionGrantsConfig, &st) == 0 &&
        static_cast<size_t>(st.st_size) > kMaxConfigBytes) {
      __android_log_print(ANDROID_LOG_ERROR, kPermissionGrantsTag,
                          "grant config too large (%lld bytes, limit %zu); "
                          "refusing to parse a truncated config",
                          static_cast<long long>(st.st_size), kMaxConfigBytes);
    }
    return -1;
  }

  int count = 0;
  char *save = nullptr;
  for (char *line = strtok_r(buf, "\n", &save); line != nullptr;
       line = strtok_r(nullptr, "\n", &save)) {
    char *hash = strchr(line, '#');
    if (hash != nullptr) *hash = '\0';
    char *pkg = line;
    while (*pkg == ' ' || *pkg == '\t') ++pkg;
    if (*pkg == '\0') continue;
    char *end = pkg + strlen(pkg);
    while (end > pkg && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r'))
      *--end = '\0';
    if (*pkg == '\0') continue;
    char *perm = pkg;
    while (*perm != '\0' && *perm != ' ' && *perm != '\t') ++perm;
    if (*perm == '\0') continue;
    *perm++ = '\0';
    while (*perm == ' ' || *perm == '\t') ++perm;
    if (*perm == '\0') continue;
    // Reject anything outside the strict Android package/permission charset
    // (which also rules out a stray trailing whitespace-separated token that
    // would otherwise be written verbatim into the name= attribute).
    if (!valid_android_name(pkg) || !valid_android_name(perm)) {
      __android_log_print(ANDROID_LOG_ERROR, kPermissionGrantsTag,
                          "skipping invalid grant rule pkg='%s' perm='%s'",
                          pkg, perm);
      continue;
    }
    if (count >= max_rules) break;
    snprintf(rules[count].package, sizeof(rules[count].package), "%s", pkg);
    snprintf(rules[count].permission, sizeof(rules[count].permission), "%s",
             perm);
    ++count;
  }
  free(buf);
  return count;
}

// Inspects the package's <perms> blocks for the named permission. Returns:
//   1  already granted (granted="true"), no change needed
//   2  present but denied (granted="false"); *false_off receives the byte
//      offset of the "false" value token so the caller can flip it to "true"
//      in place without disturbing the item's remaining attributes
//   0  package present but permission absent (a new <item> must be inserted)
//  -1  package absent
int perm_already_granted(const char *xml, size_t len, const char *package,
                         const char *permission, size_t *false_off) {
  if (false_off != nullptr) *false_off = 0;
  char open_tag[320];
  snprintf(open_tag, sizeof(open_tag), "<package name=\"%s\"", package);
  const char *pkg_start = strstr(xml, open_tag);
  if (pkg_start == nullptr) return -1;
  // Bound the scan by this package's own </package>, matching pkg_boundaries().
  // Scanning to the next "<package " (or EOF) would let the search run past a
  // trailing <shared-user> block that also contains <perms>.
  const char *pkg_end_tag = strstr(pkg_start, "</package>");
  const char *pkg_end = pkg_end_tag != nullptr && pkg_end_tag <= xml + len
      ? pkg_end_tag : xml + len;

  const char *cursor = pkg_start;
  while (cursor != nullptr && cursor < pkg_end) {
    const char *perms = strstr(cursor, "<perms>");
    if (perms == nullptr || perms >= pkg_end) break;
    const char *perms_end_tag = strstr(perms, "</perms>");
    if (perms_end_tag == nullptr || perms_end_tag >= pkg_end) break;
    const char *it = perms;
    while ((it = strstr(it, "<item ")) != nullptr && it < perms_end_tag) {
      const char *it_end = strstr(it, "/>");
      if (it_end == nullptr || it_end >= perms_end_tag) break;
      const char *nm = strstr(it, "name=\"");
      if (nm != nullptr && nm < it_end) {
        nm += 6;
        const char *nm_end = strchr(nm, '"');
        if (nm_end != nullptr && nm_end < it_end) {
          size_t name_len = static_cast<size_t>(nm_end - nm);
          if (name_len < 256 && strncmp(nm, permission, name_len) == 0 &&
              permission[name_len] == '\0') {
            const char *gr = strstr(it, "granted=\"");
            if (gr != nullptr && gr < it_end) {
              gr += 9;
              if (strncmp(gr, "true", 4) == 0) return 1;
              if (gr + 6 <= xml + len && memcmp(gr, "false\"", 6) == 0) {
                if (false_off != nullptr) {
                  *false_off = static_cast<size_t>(gr - xml);
                }
                return 2;
              }
            }
            return 0;
          }
        }
      }
      it = it_end + 2;
    }
    cursor = perms_end_tag + 8;
  }
  return 0;
}

int pkg_boundaries(const char *xml, size_t len, const char *package,
                   size_t *pkg_start_off, size_t *pkg_body_end_off) {
  char open_tag[320];
  snprintf(open_tag, sizeof(open_tag), "<package name=\"%s\"", package);
  const char *pkg_start = strstr(xml, open_tag);
  if (pkg_start == nullptr) return -1;
  const char *end_tag = strstr(pkg_start, "</package>");
  if (end_tag == nullptr || end_tag > xml + len) return -1;
  *pkg_start_off = static_cast<size_t>(pkg_start - xml);
  *pkg_body_end_off = static_cast<size_t>(end_tag - xml);
  return 0;
}

// Ensures the permission grant line exists. Returns:
//   1 already granted (no change), -1 error, 2 wrote a change (*new_xml_out set)
int ensure_perm_granted(const char *package, const char *permission,
                        char **new_xml_out, size_t *new_len_out) {
  int fd = open(kPackagesXml, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  struct stat st{};
  if (fstat(fd, &st) != 0 || st.st_size <= 0 || st.st_size > 16 * 1024 * 1024) {
    close(fd);
    return -1;
  }
  size_t len = static_cast<size_t>(st.st_size);
  char *xml = static_cast<char *>(malloc(len + 1));
  if (xml == nullptr) {
    close(fd);
    return -1;
  }
  ssize_t off = 0;
  while (off < static_cast<ssize_t>(len)) {
    ssize_t r = read(fd, xml + off, len - static_cast<size_t>(off));
    if (r < 0 && errno == EINTR) continue;
    if (r <= 0) break;
    off += r;
  }
  close(fd);
  if (off != static_cast<ssize_t>(len)) {
    free(xml);
    return -1;
  }
  xml[len] = '\0';

  size_t false_off = 0;
  int state = perm_already_granted(xml, len, package, permission, &false_off);
  if (state == 1 || state == -1) {
    free(xml);
    return state;
  }
  if (state == 2) {
    // Present but denied: flip granted="false" -> granted="true" in place,
    // preserving the item's remaining attributes (e.g. flags=) verbatim.
    // "false" is one byte longer than "true", so the document shrinks by one.
    size_t new_len = len - 1;
    char *new_xml = static_cast<char *>(malloc(new_len));
    if (new_xml == nullptr) {
      free(xml);
      return -1;
    }
    memcpy(new_xml, xml, false_off);
    memcpy(new_xml + false_off, "true", 4);
    memcpy(new_xml + false_off + 4, xml + false_off + 5,
           len - (false_off + 5));
    free(xml);
    *new_xml_out = new_xml;
    *new_len_out = new_len;
    return 2;
  }

  size_t pkg_start = 0, pkg_body_end = 0;
  if (pkg_boundaries(xml, len, package, &pkg_start, &pkg_body_end) != 0) {
    free(xml);
    return -1;
  }
  const char *pkg_start_ptr = xml + pkg_start;
  const char *pkg_end_ptr = xml + pkg_body_end;

  const char *perms = strstr(pkg_start_ptr, "<perms>");
  const char *perms_end = nullptr;
  if (perms != nullptr && perms < pkg_end_ptr) {
    perms_end = strstr(perms, "</perms>");
    if (perms_end == nullptr || perms_end >= pkg_end_ptr) perms_end = nullptr;
  }

  char item[512];
  size_t insert_off;
  if (perms_end != nullptr) {
    insert_off = static_cast<size_t>(perms_end - xml);
    snprintf(item, sizeof(item),
             "<item name=\"%s\" granted=\"true\" flags=\"0\" />", permission);
  } else {
    const char *close_tag = strstr(pkg_start_ptr, "</package>");
    if (close_tag == nullptr || close_tag >= pkg_end_ptr + strlen("</package>")) {
      free(xml);
      return -1;
    }
    insert_off = static_cast<size_t>(close_tag - xml);
    snprintf(item, sizeof(item),
             "<perms><item name=\"%s\" granted=\"true\" flags=\"0\" />"
             "</perms>", permission);
  }
  size_t item_len = strlen(item);

  size_t new_len = len + item_len;
  char *new_xml = static_cast<char *>(malloc(new_len));
  if (new_xml == nullptr) {
    free(xml);
    return -1;
  }
  memcpy(new_xml, xml, insert_off);
  memcpy(new_xml + insert_off, item, item_len);
  memcpy(new_xml + insert_off + item_len, xml + insert_off, len - insert_off);
  free(xml);

  *new_xml_out = new_xml;
  *new_len_out = new_len;
  return 2;
}

// Read a whole regular file into a freshly allocated, NUL-terminated buffer.
// Returns nullptr on any error. `max_size` bounds the read (0 disables).
char *read_whole_file(const char *path, size_t max_size, size_t *len_out) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return nullptr;
  struct stat st{};
  if (fstat(fd, &st) != 0 || st.st_size <= 0 ||
      (max_size != 0 && (size_t)st.st_size > max_size)) {
    close(fd);
    return nullptr;
  }
  size_t len = static_cast<size_t>(st.st_size);
  char *buf = static_cast<char *>(malloc(len + 1));
  if (buf == nullptr) {
    close(fd);
    return nullptr;
  }
  ssize_t off = 0;
  while (off < static_cast<ssize_t>(len)) {
    ssize_t r = read(fd, buf + off, len - static_cast<size_t>(off));
    if (r < 0 && errno == EINTR) continue;
    if (r <= 0) break;
    off += r;
  }
  close(fd);
  if (off != static_cast<ssize_t>(len)) {
    free(buf);
    return nullptr;
  }
  buf[len] = '\0';
  if (len_out != nullptr) *len_out = len;
  return buf;
}

// Atomically write `data` (len bytes) to `path` via `tmp_path`, preserving the
// metadata PackageManagerService expects for files in /data/system: uid/gid
// 1000, mode 0660, the SELinux label inherited by type transition from the
// /data/system directory, and a parent-directory fsync after the rename.
// Returns 0 on success, -1 on failure.
int write_system_file_atomic(const char *path, const char *tmp_path,
                             const char *data, size_t len) {
  int fd = open(tmp_path,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0660);
  if (fd < 0) return -1;
  int ok = fchown(fd, 1000, 1000) == 0 && fchmod(fd, 0660) == 0;
  size_t off = 0;
  while (ok && off < len) {
    ssize_t w = write(fd, data + off, len - off);
    if (w < 0 && errno == EINTR) continue;
    if (w <= 0) {
      ok = 0;
      break;
    }
    off += static_cast<size_t>(w);
  }
  if (ok) ok = fsync(fd) == 0;
  if (close(fd) != 0) ok = 0;
  if (ok) ok = rename(tmp_path, path) == 0;
  if (!ok) unlink(tmp_path);
  if (ok) {
    int dir = open("/data/system", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir >= 0) {
      (void)fsync(dir);
      close(dir);
    }
  }
  return ok ? 0 : -1;
}

// 5.6.3 validation criteria: readable, well-formed-enough XML with a <packages>
// root, a document that closes with </packages> (catches a torn write), and a
// loose minimum number of <package> elements.
int packages_xml_healthy(const char *path) {
  constexpr int kMinPackageCount = 20;
  size_t len = 0;
  char *xml = read_whole_file(path, 16 * 1024 * 1024, &len);
  if (xml == nullptr) return 0;
  int healthy = strstr(xml, "<packages") != nullptr;
  if (healthy) {
    char *end = xml + len;
    while (end > xml && (end[-1] == '\n' || end[-1] == '\r' ||
                         end[-1] == ' ' || end[-1] == '\t')) {
      --end;
    }
    static const char kClose[] = "</packages>";
    healthy = static_cast<size_t>(end - xml) >= sizeof(kClose) - 1 &&
        memcmp(end - (sizeof(kClose) - 1), kClose, sizeof(kClose) - 1) == 0;
  }
  if (healthy) {
    int count = 0;
    for (const char *cursor = xml;
         (cursor = strstr(cursor, "<package ")) != nullptr; cursor += 9) {
      ++count;
    }
    healthy = count >= kMinPackageCount;
  }
  free(xml);
  return healthy;
}

// Capture the pre-edit, PMS-readable original as the .portal-bak snapshot.
// Returns 0 if the snapshot exists (already present or newly captured),
// -1 on failure. Never overwrites an existing snapshot (it is only refreshed
// by the operator after a fully verified-good post-edit state, Step 4.5.4).
int capture_snapshot() {
  if (access(kPackagesXmlBackup, F_OK) == 0) return 0;
  size_t len = 0;
  char *xml = read_whole_file(kPackagesXml, 16 * 1024 * 1024, &len);
  if (xml == nullptr) return -1;
  int rc = write_system_file_atomic(kPackagesXmlBackup, kPackagesXmlBackupTmp,
                                    xml, len);
  free(xml);
  return rc;
}

// Fsync a directory so a just-created or just-unlinked entry survives a
// panic/watchdog reset (a non-syncing reboot). Best-effort; logs on failure.
// Defined below; declared here because restore_snapshot() uses it.
void fsync_dir(const char *path);

// Restore the .portal-bak snapshot over packages.xml and remove the stale
// packages-backup.xml sibling (5.6.2). Returns 0 on success, -1 on failure.
int restore_snapshot() {
  size_t len = 0;
  char *bak = read_whole_file(kPackagesXmlBackup, 16 * 1024 * 1024, &len);
  if (bak == nullptr) return -1;
  int rc = write_system_file_atomic(kPackagesXml, kPackagesXmlTmp, bak, len);
  free(bak);
  if (rc != 0) return -1;
  if (unlink(kPackagesXmlSystemBackup) != 0 && errno != ENOENT) {
    // A surviving stale packages-backup.xml is read preferentially by PMS on
    // the next boot (masking this restore), so this is a real failure: report
    // it so the caller keeps the recovery marker and retries next boot.
    __android_log_print(ANDROID_LOG_ERROR, kPermissionGrantsTag,
                        "stale packages-backup.xml removal failed errno=%d",
                        errno);
    return -1;
  }
  // Make the removal durable too: a stale packages-backup.xml that survives
  // a panic reset would be read preferentially by PMS and mask the restore.
  fsync_dir("/data/system");
  return 0;
}

// Fsync a directory so a just-created or just-unlinked entry survives a
// panic/watchdog reset (a non-syncing reboot). Best-effort; logs on failure.
void fsync_dir(const char *path) {
  int dir = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dir < 0) {
    __android_log_print(ANDROID_LOG_WARN, kPermissionGrantsTag,
                        "directory fsync open failed path=%s errno=%d uid=%d",
                        path, errno, getuid());
    return;
  }
  if (fsync(dir) != 0) {
    __android_log_print(ANDROID_LOG_WARN, kPermissionGrantsTag,
                        "directory fsync failed path=%s errno=%d uid=%d", path,
                        errno, getuid());
  }
  close(dir);
}

// Set the boot-time recovery marker (5.6.2) in the host priv-app's own
// system_app_data_file dir, the only helper-writable state location. The
// marker must survive a panic/watchdog reset, otherwise a needed restore
// would be silently skipped on the next boot.
void write_recovery_marker() {
  int fd = open(kPortalRestoreMarker,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) {
    __android_log_print(ANDROID_LOG_ERROR, kPermissionGrantsTag,
                        "could not set recovery marker errno=%d uid=%d", errno,
                        getuid());
    return;
  }
  static const char kNote[] = "restore packages.xml from .portal-bak\n";
  int ok = write(fd, kNote, sizeof(kNote) - 1) ==
      static_cast<ssize_t>(sizeof(kNote) - 1);
  if (ok) ok = fsync(fd) == 0;
  if (close(fd) != 0) ok = 0;
  if (ok) fsync_dir(kPortalHostDataDir);
  __android_log_print(ok ? ANDROID_LOG_WARN : ANDROID_LOG_ERROR,
                      kPermissionGrantsTag,
                      "recovery marker set ok=%d uid=%d errno=%d", ok, getuid(),
                      ok ? 0 : errno);
}

// 4.5.1 full no-op write-cycle self-test. Exercises every step the real edit
// uses: create temp -> fchown(1000:1000) -> fchmod(0660) -> rename() over a
// scratch target -> fsync parent dir -> delete. The temp file created inside
// /data/system already inherits system_data_file by type transition, so no
// relabel step is required here (or for the real edit). Returns 1 if every
// step succeeded, 0 otherwise.
int run_dryrun_self_test() {
  static const char kScratch[] =
      "/data/system/packages.xml.portal-dryrun-scratch";
  static const char kTemp[] = "/data/system/packages.xml.portal-dryrun-tmp";
  static const char kPayload[] = "portal permission grants dry-run\n";
  int fd = open(kTemp,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0660);
  __android_log_print(ANDROID_LOG_INFO, kPermissionGrantsTag,
                      "dry-run create tmp=%d uid=%d errno=%d", fd, getuid(),
                      fd < 0 ? errno : 0);
  if (fd < 0) return 0;

  int ok = fchown(fd, 1000, 1000) == 0;
  __android_log_print(ok ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
                      kPermissionGrantsTag, "dry-run fchown ok=%d errno=%d",
                      ok, ok ? 0 : errno);
  if (ok) ok = fchmod(fd, 0660) == 0;
  __android_log_print(ok ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
                      kPermissionGrantsTag, "dry-run fchmod ok=%d errno=%d",
                      ok, ok ? 0 : errno);
  if (ok) {
    ok = write(fd, kPayload, sizeof(kPayload) - 1) ==
        static_cast<ssize_t>(sizeof(kPayload) - 1);
    __android_log_print(ok ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
                        kPermissionGrantsTag, "dry-run write ok=%d errno=%d",
                        ok, ok ? 0 : errno);
  }
  if (ok) ok = fsync(fd) == 0;
  __android_log_print(ok ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
                      kPermissionGrantsTag, "dry-run fsync ok=%d errno=%d",
                      ok, ok ? 0 : errno);
  if (close(fd) != 0) ok = 0;
  if (ok) ok = rename(kTemp, kScratch) == 0;
  __android_log_print(ok ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
                      kPermissionGrantsTag, "dry-run rename ok=%d errno=%d",
                      ok, ok ? 0 : errno);
  if (ok) {
    int dir = open("/data/system", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    ok = dir >= 0 && fsync(dir) == 0;
    if (dir >= 0) close(dir);
    __android_log_print(ok ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
                        kPermissionGrantsTag,
                        "dry-run parent fsync ok=%d errno=%d", ok,
                        ok ? 0 : errno);
  }
  if (ok) ok = unlink(kScratch) == 0;
  __android_log_print(ok ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
                      kPermissionGrantsTag, "dry-run delete ok=%d errno=%d",
                      ok, ok ? 0 : errno);
  return ok;
}

// 4.5.1 defensive, non-gating relabel probe: create a file in the host
// priv-app's own (differently-labeled) data dir and attempt to relabel it to
// system_data_file, purely to characterize Meta's relabelfrom/relabelto policy
// for the record. The real edit relabels nothing.
void run_relabel_probe() {
  static const char kProbe[] =
      "/data/data/com.facebook.alohasdk.virtualcameramanager/"
      "portal-relabel-probe";
  int fd = open(kProbe,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) {
    __android_log_print(ANDROID_LOG_ERROR, kPermissionGrantsTag,
                        "relabel probe create failed errno=%d uid=%d", errno,
                        getuid());
    return;
  }
  static const char kContext[] = "u:object_r:system_data_file:s0";
  int rc = fsetxattr(fd, "security.selinux", kContext, sizeof(kContext) - 1,
                     0);
  close(fd);
  __android_log_print(rc == 0 ? ANDROID_LOG_INFO : ANDROID_LOG_WARN,
                      kPermissionGrantsTag, "relabel probe rc=%d errno=%d",
                      rc, rc == 0 ? 0 : errno);
  (void)unlink(kProbe);
}

// Re-assert the configured permission grants exactly once per boot, after PMS
// has already read packages.xml (so the edit takes effect next boot). Returns
// 0 on a clean pass, non-zero otherwise.
int activate_permission_grants() {
  // 5.6.2 recovery marker: restore the snapshot and skip all edits this boot.
  // Checked before the config read so marker handling never depends on
  // permission-grants.txt being readable (config loss is fail-safe, but a
  // skipped recovery/dry-run marker is the dangerous direction).
  if (access(kPortalRestoreMarker, F_OK) == 0) {
    __android_log_print(ANDROID_LOG_INFO, kPermissionGrantsTag,
                        "recovery marker present; restoring snapshot uid=%d",
                        getuid());
    int restored = restore_snapshot();
    if (restored == 0) {
      if (unlink(kPortalRestoreMarker) != 0 && errno != ENOENT) {
        __android_log_print(ANDROID_LOG_ERROR, kPermissionGrantsTag,
                            "recovery marker unlink failed errno=%d", errno);
      } else {
        fsync_dir(kPortalHostDataDir);
      }
      __android_log_print(ANDROID_LOG_INFO, kPermissionGrantsTag,
                          "snapshot restored; marker cleared uid=%d",
                          getuid());
    } else {
      __android_log_print(ANDROID_LOG_ERROR, kPermissionGrantsTag,
                          "snapshot restore failed errno=%d; marker kept",
                          errno);
    }
    return restored == 0 ? 0 : 1;
  }

  // 4.5.1 dry-run marker: no-op write-cycle self-test, NO packages.xml edit.
  if (access(kPortalDryrunMarker, F_OK) == 0) {
    __android_log_print(ANDROID_LOG_INFO, kPermissionGrantsTag,
                        "dry-run marker present; running self-test uid=%d",
                        getuid());
    int self_test_ok = run_dryrun_self_test();
    run_relabel_probe();
    if (self_test_ok) {
      if (unlink(kPortalDryrunMarker) != 0 && errno != ENOENT) {
        __android_log_print(ANDROID_LOG_ERROR, kPermissionGrantsTag,
                            "dry-run marker unlink failed errno=%d", errno);
      } else {
        fsync_dir(kPortalHostDataDir);
      }
      __android_log_print(ANDROID_LOG_INFO, kPermissionGrantsTag,
                          "dry-run self-test passed; marker cleared, no edit "
                          "this boot uid=%d",
                          getuid());
    } else {
      __android_log_print(ANDROID_LOG_ERROR, kPermissionGrantsTag,
                          "dry-run self-test FAILED; marker kept, no edit "
                          "this boot errno=%d",
                          errno);
    }
    return self_test_ok ? 0 : 1;
  }

  GrantRule rules[32];
  int count = read_grant_config(rules, 32);
  if (count <= 0) {
    __android_log_print(ANDROID_LOG_ERROR, kPermissionGrantsTag,
                        "no grant config at %s (count=%d) uid=%d",
                        kPermissionGrantsConfig, count, getuid());
    return 1;
  }

  // 5.6.3(i): validate the file PMS just read before touching it.
  if (!packages_xml_healthy(kPackagesXml)) {
    write_recovery_marker();
    __android_log_print(ANDROID_LOG_ERROR, kPermissionGrantsTag,
                        "packages.xml unhealthy on boot; recovery marker set "
                        "uid=%d",
                        getuid());
    return 1;
  }

  // 5.4: reconcile the stale packages-backup.xml sibling BEFORE editing, so
  // PMS reads the edited primary (not a stale backup) on the next boot. This
  // runs on every boot that reaches this point (including an idempotent one
  // where the permission is already granted): a surviving stale backup would
  // otherwise be read preferentially by PMS and mask an already-granted
  // primary. A failure to remove it is an error for the same reason.
  bool any_error = false;
  if (access(kPackagesXmlSystemBackup, F_OK) == 0) {
    if (unlink(kPackagesXmlSystemBackup) != 0 && errno != ENOENT) {
      any_error = true;
      __android_log_print(ANDROID_LOG_ERROR, kPermissionGrantsTag,
                          "stale packages-backup.xml removal failed errno=%d",
                          errno);
    } else {
      // Durability: a stale packages-backup.xml that survives a panic reset
      // would be read preferentially by PMS and mask the edited primary.
      fsync_dir("/data/system");
      __android_log_print(ANDROID_LOG_INFO, kPermissionGrantsTag,
                          "stale packages-backup.xml removed uid=%d",
                          getuid());
    }
  }

  bool wrote_any = false;
  for (int i = 0; i < count; ++i) {
    char *new_xml = nullptr;
    size_t new_len = 0;
    int rc = ensure_perm_granted(rules[i].package, rules[i].permission,
                                 &new_xml, &new_len);
    if (rc == 1) {
      __android_log_print(ANDROID_LOG_INFO, kPermissionGrantsTag,
                          "grant already present pkg=%s perm=%s",
                          rules[i].package, rules[i].permission);
    } else if (rc == 2) {
      if (!wrote_any) {
        int snap = capture_snapshot();
        if (snap != 0) {
          free(new_xml);
          __android_log_print(ANDROID_LOG_ERROR, kPermissionGrantsTag,
                              "snapshot capture failed; aborting edit "
                              "errno=%d",
                              errno);
          return 1;
        }
        __android_log_print(ANDROID_LOG_INFO, kPermissionGrantsTag,
                            "pre-edit snapshot captured uid=%d", getuid());
      }
      int wr = write_system_file_atomic(kPackagesXml, kPackagesXmlTmp, new_xml,
                                        new_len);
      free(new_xml);
      if (wr == 0) {
        wrote_any = true;
        __android_log_print(ANDROID_LOG_INFO, kPermissionGrantsTag,
                            "granted pkg=%s perm=%s uid=%d", rules[i].package,
                            rules[i].permission, getuid());
      } else {
        any_error = true;
        __android_log_print(ANDROID_LOG_ERROR, kPermissionGrantsTag,
                            "write failed pkg=%s perm=%s errno=%d",
                            rules[i].package, rules[i].permission, errno);
      }
    } else {
      any_error = true;
      __android_log_print(ANDROID_LOG_ERROR, kPermissionGrantsTag,
                          "ensure failed pkg=%s perm=%s rc=%d errno=%d",
                          rules[i].package, rules[i].permission, rc, errno);
    }
  }

  if (wrote_any) {
    // 5.6.3(ii): self-validate the freshly-written output in the same boot.
    if (!packages_xml_healthy(kPackagesXml)) {
      write_recovery_marker();
      __android_log_print(ANDROID_LOG_ERROR, kPermissionGrantsTag,
                          "post-edit validation FAILED; recovery marker set "
                          "uid=%d",
                          getuid());
      return 1;
    }
    __android_log_print(ANDROID_LOG_INFO, kPermissionGrantsTag,
                        "post-edit validation passed uid=%d", getuid());
  }
  // A clean idempotent pass (every rule already granted) returns 0. Any rule
  // that could not be ensured or written must fail the run rather than
  // silently exiting 0 with nothing done.
  return any_error ? 1 : 0;
}

}  // namespace

int portal_watchdog_main(int argc, char **argv) {
  prctl(PR_SET_NAME, "portal-led-watch", 0, 0, 0);
  int singleton = claim_singleton();
  if (singleton < 0) {
    __android_log_print(ANDROID_LOG_INFO, kTag,
                        "watchdog already running or socket unavailable: %s",
                        strerror(errno));
    return 0;
  }

  signal(SIGTERM, stop);
  signal(SIGINT, stop);

  bool camera_enabled = access(kCameraEnabled, R_OK) == 0;
  // Omni's production init rules stop adbd after persistent properties load.
  // Treat its persisted TCP port as the durable request too, so a reboot can
  // recover even if the exploit copied this binary but reset before writing
  // the companion marker.
  bool wireless_adb_enabled =
      access(kWirelessAdbEnabled, R_OK) == 0 ||
      omni_wireless_adb_requested();
  bool system_theme_control_enabled =
      access(kSystemThemeControlEnabled, R_OK) == 0;
  bool adb_framework_enabled =
      access(kAdbFrameworkEnabled, R_OK) == 0;
  bool permission_grants_enabled =
      access(kPermissionGrantsConfig, R_OK) == 0;
  int presence_fps = read_presence_fps();
  for (int index = 1; index < argc; ++index) {
    if (strcmp(argv[index], "--camera") == 0) {
      camera_enabled = true;
    } else if (strcmp(argv[index], "--fps") == 0 && index + 1 < argc) {
      char *end = nullptr;
      long value = strtol(argv[++index], &end, 10);
      if (end != nullptr && *end == '\0' && value >= 1 && value <= 10) {
        presence_fps = static_cast<int>(value);
      }
    } else if (strcmp(argv[index], "--adb-framework") == 0) {
      adb_framework_enabled = true;
    } else if (strcmp(argv[index], "--grant-permissions") == 0) {
      permission_grants_enabled = true;
    }
  }
  pid_t presence_worker = -1;
  if (presence_fps != 0) {
    presence_worker = fork();
    if (presence_worker == 0) {
      close(singleton);
      activate_presence(presence_fps);
    }
    if (presence_worker < 0) {
      __android_log_print(ANDROID_LOG_ERROR, kPresenceTag,
                          "could not start presence worker uid=%d: %s",
                          getuid(), strerror(errno));
    }
  }
  pid_t wireless_adb_worker = -1;
  if (wireless_adb_enabled) {
    wireless_adb_worker = fork();
    if (wireless_adb_worker == 0) {
      close(singleton);
      activate_wireless_adb();
    }
    if (wireless_adb_worker < 0) {
      __android_log_print(ANDROID_LOG_ERROR, kTag,
                          "could not start wireless ADB worker uid=%d: %s",
                          getuid(), strerror(errno));
    }
  }
  pid_t adb_framework_worker = -1;
  if (adb_framework_enabled) {
    adb_framework_worker = fork();
    if (adb_framework_worker == 0) {
      close(singleton);
      activate_adb_framework();
    }
    if (adb_framework_worker < 0) {
      __android_log_print(ANDROID_LOG_ERROR, kAdbFrameworkTag,
                          "could not start worker uid=%d: %s",
                          getuid(), strerror(errno));
    }
  }
  pid_t system_theme_worker = -1;
  if (system_theme_control_enabled) {
    system_theme_worker = fork();
    if (system_theme_worker == 0) {
      close(singleton);
      activate_system_theme_control();
    }
    if (system_theme_worker < 0) {
      __android_log_print(ANDROID_LOG_ERROR, kSystemThemeTag,
                          "could not start system theme worker uid=%d: %s",
                          getuid(), strerror(errno));
    }
  }
  pid_t permission_grants_worker = -1;
  if (permission_grants_enabled) {
    permission_grants_worker = fork();
    if (permission_grants_worker == 0) {
      close(singleton);
      _exit(activate_permission_grants());
    }
    if (permission_grants_worker < 0) {
      __android_log_print(ANDROID_LOG_ERROR, kPermissionGrantsTag,
                          "could not start permission grant worker uid=%d: %s",
                          getuid(), strerror(errno));
    }
  }

  if (!camera_enabled) {
    if (presence_worker > 0) {
      int status = 0;
      while (waitpid(presence_worker, &status, 0) < 0 && errno == EINTR) {}
    }
    if (wireless_adb_worker > 0) {
      int status = 0;
      while (waitpid(wireless_adb_worker, &status, 0) < 0 && errno == EINTR) {}
    }
    if (adb_framework_worker > 0) {
      int status = 0;
      while (waitpid(adb_framework_worker, &status, 0) < 0 &&
             errno == EINTR) {}
    }
    if (system_theme_worker > 0) {
      int status = 0;
      while (waitpid(system_theme_worker, &status, 0) < 0 && errno == EINTR) {}
    }
    if (permission_grants_worker > 0) {
      int status = 0;
      while (waitpid(permission_grants_worker, &status, 0) < 0 && errno == EINTR) {}
    }
    close(singleton);
    return presence_fps != 0 || wireless_adb_enabled ||
        adb_framework_enabled || system_theme_control_enabled ||
        permission_grants_enabled ? 0 : 1;
  }

  void *library = dlopen(kClientLibrary, RTLD_NOW | RTLD_LOCAL);
  if (library == nullptr) {
    __android_log_print(ANDROID_LOG_ERROR, kTag, "dlopen failed: %s",
                        dlerror());
    return 1;
  }
  real_log_vprint = reinterpret_cast<LogVPrint>(
      dlsym(RTLD_DEFAULT, "__android_log_vprint"));
  dl_iterate_phdr(silence_privacy_client_logs, nullptr);
  auto constructor = reinterpret_cast<Constructor>(symbol(library, kConstructor));
  auto destructor = reinterpret_cast<Destructor>(symbol(library, kDestructor));
  auto connect = reinterpret_cast<ConnectMethod>(symbol(library, kConnect));
  auto disconnect = reinterpret_cast<VoidMethod>(symbol(library, kDisconnect));
  auto clear = reinterpret_cast<BoolMethod>(symbol(library, kClear));
  auto get = reinterpret_cast<BoolMethod>(symbol(library, kGet));
  if (constructor == nullptr || destructor == nullptr || connect == nullptr ||
      disconnect == nullptr || clear == nullptr || get == nullptr) {
    dlclose(library);
    return 1;
  }

  alignas(16) unsigned char client[0x100]{};
  constructor(client, 0, 0, true);
  bool connected = connect(client) == 0;
  __android_log_print(ANDROID_LOG_INFO, kTag,
                      "watchdog started uid=%d", getuid());
  if (connected) {
    __android_log_print(ANDROID_LOG_INFO, kTag,
                        "watchdog connected uid=%d", getuid());
  }

  unsigned failures = 0;
  unsigned reconnect_ticks = 0;
  unsigned heartbeat_ticks = 0;
  while (running) {
    if (!connected) {
      if (++reconnect_ticks >= 20) {
        reconnect_ticks = 0;
        connected = connect(client) == 0;
        if (connected) {
          failures = 0;
          __android_log_print(ANDROID_LOG_INFO, kTag,
                              "watchdog connected uid=%d", getuid());
        }
      }
    } else {
      bool should_clear = get(client) || ++heartbeat_ticks >= 240;
      if (should_clear) {
        heartbeat_ticks = 0;
        if (clear(client)) {
          failures = 0;
        } else if (++failures >= 20) {
          __android_log_print(ANDROID_LOG_WARN, kTag,
                              "clearLed failed; reconnecting");
          disconnect(client);
          connected = false;
          failures = 0;
          reconnect_ticks = 0;
        }
      }
    }
    usleep(250000);
  }

  if (connected) disconnect(client);
  __android_log_print(ANDROID_LOG_INFO, kTag,
                      "watchdog exiting signal=%d", stop_signal);
  destructor(client);
  dlclose(library);
  close(singleton);
  return 0;
}

#ifndef PORTAL_WATCHDOG_LIBRARY
int main(int argc, char **argv) {
  return portal_watchdog_main(argc, argv);
}
#endif
