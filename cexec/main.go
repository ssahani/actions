package main

import (
    "bytes"
    "fmt"
    "io"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
    "strings"
    "time"

    log "github.com/sirupsen/logrus"
)

// MountConfig holds configuration for mounting operations
type MountConfig struct {
    RootPath     string // Path where root partition will be mounted
    BootPath     string // Path where boot partition will be mounted
    LuksName     string // Name for LUKS encrypted device mapping
    KeyFile      string // Path to LUKS keyfile
    MappedDevice string // Path to mapped LUKS device
}

// DeviceConfig holds configuration for device operations
type DeviceConfig struct {
    BlockDevice string // Path to encrypted device/partition
    BootDevice  string // Path to boot device/partition
    FsType      string // Filesystem type for root partition
    BootFsType  string // Filesystem type for boot partition
}

// ChrootConfig holds configuration for chroot operations
type ChrootConfig struct {
    Commands         []string // List of commands to execute in chroot
    Interpreter      string   // Command interpreter for chroot commands
    ChrootEnabled    bool     // Whether chroot execution is enabled
    UpdateResolvConf bool     // Whether to copy resolv.conf for network
    DebianFrontend   string   // DEBIAN_FRONTEND environment variable
}

func main() {
    // Initialize logging
    configureLogging()

    // Record startup time and log initialization
    startTime := time.Now()
    logStartupInfo()

    // Ensure completion logs are recorded
    defer func() {
        logCompletionInfo(startTime)
    }()

    log.Info("✅ Starting chroot command execution with LUKS support")

    // Check user privileges
    checkPrivileges()

    // Initialize mount configuration
    mountCfg := &MountConfig{
        LuksName:     "cryptroot",
        RootPath:     determineMountPath("root"),
        BootPath:     determineMountPath("boot"),
    }
    mountCfg.MappedDevice = "/dev/mapper/" + mountCfg.LuksName
    mountCfg.KeyFile = filepath.Join(mountCfg.BootPath, "root_crypt.key")

    // Process configurations
    devCfg := processDeviceConfig()
    chrootCfg := processChrootConfig()

    // Execute workflow
    if err := executeWorkflow(mountCfg, devCfg, chrootCfg); err != nil {
        log.WithError(err).Fatal("❌ Workflow execution failed")
    }
}

// configureLogging sets up logging with custom formatting
func configureLogging() {
    log.SetFormatter(&log.TextFormatter{
        FullTimestamp:   true,
        TimestampFormat: time.RFC3339Nano,
        PadLevelText:    true,
    })
    log.SetLevel(log.DebugLevel)
    var logBuffer bytes.Buffer
    mw := io.MultiWriter(os.Stdout, &logBuffer)
    log.SetOutput(mw)
}

// logStartupInfo logs initial system and process information
func logStartupInfo() {
    envVars := make(map[string]string)
    for _, env := range os.Environ() {
        if i := strings.Index(env, "="); i >= 0 {
            key := env[:i]
            lowerKey := strings.ToLower(key)
            if strings.Contains(lowerKey, "key") || strings.Contains(lowerKey, "pass") || strings.Contains(lowerKey, "secret") {
                envVars[key] = "*****MASKED*****"
            } else {
                envVars[key] = env[i+1:]
            }
        }
    }

    log.WithFields(log.Fields{
        "start_time":  time.Now().Format(time.RFC3339Nano),
        "pid":         os.Getpid(),
        "ppid":        os.Getppid(),
        "uid":         os.Getuid(),
        "gid":         os.Getgid(),
        "go_version":  runtime.Version(),
        "environment": envVars,
    }).Info("🚀 Starting chroot command execution")
}

// logCompletionInfo logs completion metrics
func logCompletionInfo(startTime time.Time) {
    duration := time.Since(startTime)
    log.WithFields(log.Fields{
        "duration_seconds": duration.Seconds(),
        "end_time":         time.Now().Format(time.RFC3339Nano),
    }).Info("🏁 Operation completed")
}

// checkPrivileges verifies root privileges
func checkPrivileges() {
    if os.Getuid() != 0 {
        log.Warn("⚠️ Running as non-root user - using sudo for privileged operations")
        if _, err := exec.LookPath("sudo"); err != nil {
            log.Fatal("❌ sudo not found - required for non-root operation")
        }
    } else {
        log.Info("✅ Running as root user")
    }
}

// determineMountPath finds a suitable mount point
func determineMountPath(baseName string) string {
    candidates := []string{
        filepath.Join("/mnt", baseName),
        filepath.Join("/tmp/mnt", baseName),
        filepath.Join("./mnt", baseName),
    }

    for _, path := range candidates {
        if testDirectoryWritable(path) {
            log.WithField("path", path).Debugf("Using %s mount directory", baseName)
            return path
        }
    }

    log.Warnf("No %s mount directory available, using fallback", baseName)
    return filepath.Join("./mnt", baseName)
}

// testDirectoryWritable checks if a directory is writable
func testDirectoryWritable(path string) bool {
    if err := os.MkdirAll(path, 0755); err != nil {
        log.WithError(err).Debugf("Failed to create directory %s", path)
        return false
    }

    testFile := filepath.Join(path, ".test_write")
    if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
        log.WithError(err).Debugf("Failed to write test file in %s", path)
        _ = os.RemoveAll(path)
        return false
    }
    _ = os.Remove(testFile)
    return true
}

// processDeviceConfig processes device-related environment variables
func processDeviceConfig() *DeviceConfig {
    cfg := &DeviceConfig{
        BlockDevice: os.Getenv("BLOCK_DEVICE"),
        BootDevice:  os.Getenv("BOOT_DISK"),
        FsType:      os.Getenv("FS_TYPE"),
        BootFsType:  os.Getenv("BOOT_FS_TYPE"),
    }

    if cfg.BlockDevice == "" {
        cfg.BlockDevice = "/dev/sda3"
        log.Warn("Using default block device: /dev/sda3")
    }
    if cfg.BootDevice == "" {
        cfg.BootDevice = "/dev/sda2"
        log.Warn("Using default boot device: /dev/sda2")
    }
    if cfg.FsType == "" {
        cfg.FsType = "ext4"
        log.Warn("Using default filesystem: ext4")
    }
    if cfg.BootFsType == "" {
        cfg.BootFsType = "ext4"
        log.Warn("Using default boot filesystem: ext4")
    }

    if cfg.BlockDevice == "" || cfg.BootDevice == "" {
        logDeviceInfo()
        log.Fatal("❌ BLOCK_DEVICE and BOOT_DISK must be specified or defaults used")
    }

    log.WithFields(log.Fields{
        "block_device":  cfg.BlockDevice,
        "boot_device":   cfg.BootDevice,
        "fs_type":       cfg.FsType,
        "boot_fs_type":  cfg.BootFsType,
    }).Info("📌 Using device configuration")

    return cfg
}

// processChrootConfig processes chroot-related environment variables
func processChrootConfig() *ChrootConfig {
    commandsStr := os.Getenv("CMD_LINE")
    var commands []string
    if commandsStr != "" {
        commands = strings.Split(commandsStr, ";")
        for i, cmd := range commands {
            commands[i] = strings.TrimSpace(cmd)
        }
    }

    if len(commands) == 0 {
        log.Fatal("❌ CMD_LINE must be specified")
    }

    interpreter := os.Getenv("DEFAULT_INTERPRETER")
    if interpreter == "" {
        interpreter = "/bin/sh -c"
        log.Warn("Using default interpreter: /bin/sh -c")
    }

    chrootEnabled := strings.ToLower(os.Getenv("CHROOT")) == "y"
    updateResolvConf := strings.ToLower(os.Getenv("UPDATE_RESOLV_CONF")) == "true"
    debianFrontend := os.Getenv("DEBIAN_FRONTEND")
    if debianFrontend == "" {
        debianFrontend = "noninteractive"
        log.Warn("Using default DEBIAN_FRONTEND: noninteractive")
    }

    cfg := &ChrootConfig{
        Commands:         commands,
        Interpreter:      interpreter,
        ChrootEnabled:    chrootEnabled,
        UpdateResolvConf: updateResolvConf,
        DebianFrontend:   debianFrontend,
    }

    log.WithFields(log.Fields{
        "commands":          cfg.Commands,
        "interpreter":       cfg.Interpreter,
        "chroot_enabled":    cfg.ChrootEnabled,
        "update_resolv_conf": cfg.UpdateResolvConf,
        "debian_frontend":   cfg.DebianFrontend,
    }).Info("📌 Using chroot configuration")

    return cfg
}

// executeWorkflow orchestrates the disk setup and chroot execution
func executeWorkflow(mountCfg *MountConfig, devCfg *DeviceConfig, chrootCfg *ChrootConfig) error {
    if !chrootCfg.ChrootEnabled {
        log.Info("⏭️ Chroot disabled, skipping execution")
        return nil
    }

    if err := createMountDirs(mountCfg.RootPath, mountCfg.BootPath); err != nil {
        return fmt.Errorf("failed to create mount directories: %w", err)
    }

    if err := mountWithRetry(devCfg.BootDevice, mountCfg.BootPath, devCfg.BootFsType, 3); err != nil {
        return fmt.Errorf("failed to mount boot device: %w", err)
    }
    defer unmountDevice(mountCfg.BootPath)

    if err := verifyKeyfile(mountCfg.KeyFile); err != nil {
        return fmt.Errorf("LUKS keyfile verification failed: %w", err)
    }

    if err := handleLUKSOperations(devCfg.BlockDevice, mountCfg.LuksName, mountCfg.KeyFile, mountCfg.MappedDevice); err != nil {
        return err
    }
    defer closeLUKSDevice(mountCfg.LuksName)

    if err := mountWithRetry(mountCfg.MappedDevice, mountCfg.RootPath, devCfg.FsType, 3); err != nil {
        return fmt.Errorf("failed to mount root partition: %w", err)
    }
    defer unmountDevice(mountCfg.RootPath)

    if err := setupAndRunChroot(mountCfg.RootPath, chrootCfg); err != nil {
        return fmt.Errorf("failed to execute chroot commands: %w", err)
    }

    return nil
}

// setupAndRunChroot sets up the chroot environment and runs commands
func setupAndRunChroot(rootPath string, chrootCfg *ChrootConfig) error {
    log.WithField("root_path", rootPath).Info("🔧 Setting up chroot environment")

    essentialMounts := []struct {
        source string
        target string
        fsType string
    }{
        {"/dev", filepath.Join(rootPath, "dev"), "devtmpfs"},
        {"/proc", filepath.Join(rootPath, "proc"), "proc"},
        {"/sys", filepath.Join(rootPath, "sys"), "sysfs"},
        {"/dev/pts", filepath.Join(rootPath, "dev/pts"), "devpts"},
    }

    for _, mount := range essentialMounts {
        targetPath := mount.target
        if err := createMountDirs(targetPath); err != nil {
            return fmt.Errorf("failed to create mount directory %s: %w", targetPath, err)
        }
        if err := mountWithRetry(mount.source, targetPath, mount.fsType, 3); err != nil {
            return fmt.Errorf("failed to mount %s on %s: %w", mount.source, targetPath, err)
        }
        defer unmountDevice(targetPath)
    }

    if chrootCfg.UpdateResolvConf {
        resolvConfSrc := "/etc/resolv.conf"
        resolvConfDst := filepath.Join(rootPath, "etc/resolv.conf")
        if _, err := os.Stat(resolvConfSrc); err == nil {
            if err := runPrivileged("cp", resolvConfSrc, resolvConfDst); err != nil {
                log.WithError(err).Warn("⚠️ Failed to copy resolv.conf")
            } else {
                log.WithField("path", resolvConfDst).Info("📌 Copied resolv.conf")
                defer runPrivileged("rm", "-f", resolvConfDst)
            }
        }
    }

    for _, cmd := range chrootCfg.Commands {
        if err := runChrootCommand(rootPath, cmd, chrootCfg); err != nil {
            return fmt.Errorf("failed to execute chroot command '%s': %w", cmd, err)
        }
    }

    log.WithField("root_path", rootPath).Info("✅ Chroot operations completed")
    return nil
}

// runChrootCommand executes a command in the chroot environment
func runChrootCommand(rootPath, command string, chrootCfg *ChrootConfig) error {
    log.WithFields(log.Fields{
        "root_path": rootPath,
        "command":   command,
    }).Info("🔄 Executing command in chroot")

    args := []string{rootPath}
    args = append(args, strings.Fields(chrootCfg.Interpreter)...)
    args = append(args, command)

    var cmd *exec.Cmd
    if os.Getuid() != 0 {
        cmd = exec.Command("sudo", append([]string{"chroot"}, args...)...)
    } else {
        cmd = exec.Command("chroot", args...)
    }

    cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND="+chrootCfg.DebianFrontend)

    output, err := cmd.CombinedOutput()
    log.WithFields(log.Fields{
        "command":   cmd.String(),
        "exit_code": getExitCode(err),
        "output":    string(output),
    }).Debug("Chroot command execution")

    if err != nil {
        return fmt.Errorf("chroot command failed: %w\nOutput: %s", err, string(output))
    }

    log.WithField("command", command).Info("✅ Chroot command executed successfully")
    return nil
}

// mountWithRetry attempts to mount a device with retries
func mountWithRetry(device, mountPoint, fsType string, retries int) error {
    var lastError error
    for i := 0; i < retries; i++ {
        log.WithFields(log.Fields{
            "attempt":   i + 1,
            "max_tries": retries,
            "device":    device,
        }).Debug("Mount attempt")

        if err := mountDevice(device, mountPoint, fsType); err == nil {
            return nil
        } else {
            lastError = err
            time.Sleep(time.Second * time.Duration(i+1))
        }
    }
    return fmt.Errorf("after %d attempts: %w", retries, lastError)
}

// mountDevice performs the mount operation
func mountDevice(device, mountPoint, fsType string) error {
    if fsType != "proc" && fsType != "sysfs" && fsType != "devtmpfs" && fsType != "devpts" {
        if err := verifyDevice(device); err != nil {
            return err
        }
    }

    args := []string{"-v"}
    if fsType != "" {
        args = append(args, "-t", fsType)
    }
    args = append(args, device, mountPoint)

    if err := runPrivileged("mount", args...); err != nil {
        return fmt.Errorf("mount failed: %w", err)
    }

    log.WithFields(log.Fields{
        "device":      device,
        "mount_point": mountPoint,
        "fs_type":     fsType,
    }).Info("✅ Mount successful")
    return nil
}

// verifyDevice checks if a path is a valid block device
func verifyDevice(device string) error {
    info, err := os.Stat(device)
    if err != nil {
        return fmt.Errorf("device %s stat failed: %w", device, err)
    }
    if (info.Mode() & os.ModeDevice) == 0 {
        return fmt.Errorf("%s is not a device file", device)
    }
    return nil
}

// unmountDevice un_mounts a filesystem
func unmountDevice(mountPoint string) error {
    log.WithField("mount_point", mountPoint).Debug("Unmounting device")
    if err := runPrivileged("umount", "-v", mountPoint); err != nil {
        return fmt.Errorf("unmount failed: %w", err)
    }
    return nil
}

// verifyKeyfile checks LUKS keyfile properties
func verifyKeyfile(keyFile string) error {
    info, err := os.Stat(keyFile)
    if err != nil {
        return fmt.Errorf("keyfile stat failed: %w", err)
    }
    if info.Size() == 0 {
        return fmt.Errorf("keyfile is empty")
    }
    if mode := info.Mode().Perm(); mode != 0400 {
        log.WithFields(log.Fields{
            "key_file":    keyFile,
            "permissions": fmt.Sprintf("%#o", mode),
        }).Warn("⚠️ LUKS keyfile has insecure permissions")
    }
    log.WithFields(log.Fields{
        "key_file":    keyFile,
        "size_bytes":  info.Size(),
        "permissions": fmt.Sprintf("%#o", info.Mode().Perm()),
    }).Info("✅ LUKS keyfile verified")
    return nil
}

// handleLUKSOperations manages LUKS device mapping
func handleLUKSOperations(blockDevice, luksName, keyFile, mappedDevice string) error {
    log.WithFields(log.Fields{
        "block_device": blockDevice,
        "luks_name":    luksName,
        "key_file":     keyFile,
    }).Info("🔓 Attempting to unlock LUKS device")

    cmdArgs := []string{
        "luksOpen",
        blockDevice,
        luksName,
        "--key-file", keyFile,
        "--verbose",
    }

    if err := runPrivileged("cryptsetup", cmdArgs...); err != nil {
        log.WithFields(log.Fields{
            "error":        err,
            "block_device": blockDevice,
            "key_file":     keyFile,
        }).Error("❌ Failed to unlock LUKS device")
        return fmt.Errorf("LUKS unlock failed: %w", err)
    }

    log.WithFields(log.Fields{
        "mapped_device":   mappedDevice,
        "original_device": blockDevice,
    }).Info("✅ LUKS device unlocked")
    return nil
}

// closeLUKSDevice closes a mapped LUKS device
func closeLUKSDevice(name string) {
    log.WithField("luks_name", name).Info("🔒 Closing LUKS device")
    if err := runPrivileged("cryptsetup", "luksClose", name); err != nil {
        log.WithError(err).Warn("⚠️ Failed to close LUKS device")
    }
}

// createMountDirs creates mount point directories
func createMountDirs(paths ...string) error {
    for _, path := range paths {
        log.WithField("directory", path).Debug("Creating directory")
        if err := runPrivileged("mkdir", "-p", path); err != nil {
            return fmt.Errorf("failed to create directory %s: %w", path, err)
        }
        if err := runPrivileged("chmod", "755", path); err != nil {
            return fmt.Errorf("failed to set permissions for %s: %w", path, err)
        }
    }
    return nil
}

// runPrivileged executes a command with sudo if not root
func runPrivileged(name string, args ...string) error {
    var cmd *exec.Cmd
    if os.Getuid() != 0 {
        fullArgs := append([]string{name}, args...)
        cmd = exec.Command("sudo", fullArgs...)
    } else {
        cmd = exec.Command(name, args...)
    }

    output, err := cmd.CombinedOutput()
    log.WithFields(log.Fields{
        "command":   cmd.String(),
        "exit_code": getExitCode(err),
        "output":    string(output),
    }).Debug("Command execution")

    if err != nil {
        return fmt.Errorf("command failed: %w\nOutput: %s", err, string(output))
    }
    return nil
}

// getExitCode extracts the exit code from an error
func getExitCode(err error) int {
    if err == nil {
        return 0
    }
    if exitErr, ok := err.(*exec.ExitError); ok {
        return exitErr.ExitCode()
    }
    return -1
}

// logDeviceInfo logs detailed device information
func logDeviceInfo() {
    commands := []struct {
        name string
        args []string
    }{
        {"lsblk", []string{"-f", "-o", "NAME,FSTYPE,FSVER,LABEL,UUID,MOUNTPOINT,SIZE,MODEL"}},
        {"blkid", nil},
        {"ls", []string{"-la", "/dev"}},
    }

    for _, cmd := range commands {
        output, err := exec.Command(cmd.name, cmd.args...).CombinedOutput()
        log.WithFields(log.Fields{
            "command":   fmt.Sprintf("%s %v", cmd.name, cmd.args),
            "exit_code": getExitCode(err),
            "output":    string(output),
        }).Info("Device information")
    }
}
