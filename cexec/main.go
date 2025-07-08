package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
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

// ExecConfig holds configuration for command execution
type ExecConfig struct {
	Command         string // Command to execute
	Interpreter     string // Command interpreter to use
	ChrootPath      string // Path to chroot into
	UpdateResolv    bool   // Whether to update resolv.conf in chroot
	DefaultRootPath string // Default path for root mount
}

// DeviceConfig holds configuration for device operations
type DeviceConfig struct {
	EncryptedDevice string // Path to encrypted device/partition
	BootDevice      string // Path to boot device/partition
	RootFsType      string // Filesystem type for root partition
	BootFsType      string // Filesystem type for boot partition
}

func main() {
	// Initialize logging configuration
	configureLogging()

	// Log environment variables at startup (masking sensitive ones)
	logEnvironment()

	// Set up context with signal handling for graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Record startup time and log initialization info
	startTime := time.Now()
	logStartupInfo()

	// Ensure completion logs are always recorded
	defer func() {
		logCompletionInfo(startTime)
	}()

	log.Info("✅ Running cexec with LUKS Support")

	// Check and log user privileges
	checkPrivileges()

	// Initialize mount configuration with defaults
	mountCfg := &MountConfig{
		LuksName: "cryptroot", // Default LUKS device name
		RootPath: determineMountPath("root"),
		BootPath: determineMountPath("boot"),
	}
	mountCfg.MappedDevice = "/dev/mapper/" + mountCfg.LuksName
	mountCfg.KeyFile = "root_crypt.key"

	// Process device configuration from environment variables
	devCfg := processDeviceConfig()
	// Process execution configuration from environment variables
	execCfg := processExecConfig()

	// Execute main workflow with the configured parameters
	if err := executeWorkflow(ctx, mountCfg, devCfg, execCfg); err != nil {
		log.WithError(err).Fatal("❌ Workflow execution failed")
	}
}

// logEnvironment logs all environment variables (masking sensitive ones)
func logEnvironment() {
	envVars := make(map[string]string)
	for _, env := range os.Environ() {
		if i := strings.Index(env, "="); i >= 0 {
			key := env[:i]
			// Mask sensitive values (case-insensitive check)
			lowerKey := strings.ToLower(key)
			if strings.Contains(lowerKey, "key") || strings.Contains(lowerKey, "pass") || strings.Contains(lowerKey, "secret") {
				envVars[key] = "*****MASKED*****"
			} else {
				envVars[key] = env[i+1:]
			}
		}
	}
	log.WithFields(log.Fields{
		"environment": envVars,
	}).Info("🌍 Environment variables")
}

// configureLogging sets up the logging system with custom formatting
func configureLogging() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339Nano,
		PadLevelText:    true,
	})

	// Set log level based on environment
	if os.Getenv("DEBUG") == "true" {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	// Set up multi-writer to output to both stdout and a buffer
	var logBuffer bytes.Buffer
	mw := io.MultiWriter(os.Stdout, &logBuffer)
	log.SetOutput(mw)
}

// logStartupInfo records initial system and process information
func logStartupInfo() {
	log.WithFields(log.Fields{
		"start_time": time.Now().Format(time.RFC3339Nano),
		"pid":        os.Getpid(),
		"ppid":       os.Getppid(),
		"uid":        os.Getuid(),
		"gid":        os.Getgid(),
		"go_version": runtime.Version(),
	}).Info("🚀 Starting command execution environment")
}

// logCompletionInfo records completion metrics and timing information
func logCompletionInfo(startTime time.Time) {
	duration := time.Since(startTime)
	log.WithFields(log.Fields{
		"duration_seconds": duration.Seconds(),
		"end_time":         time.Now().Format(time.RFC3339Nano),
	}).Info("🏁 Operation completed")
}

// checkPrivileges verifies if the process is running with root privileges
func checkPrivileges() {
	if os.Getuid() != 0 {
		log.Warn("⚠️ Running as non-root user - will use sudo for privileged operations")
		if _, err := exec.LookPath("sudo"); err != nil {
			log.Fatal("❌ sudo not found - required for non-root operation")
		}
	} else {
		log.Info("✅ Running as root user")
	}
}

// determineMountPath finds a suitable mount point from candidate paths
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

// testDirectoryWritable checks if a directory is writable by creating a test file
func testDirectoryWritable(path string) bool {
	log.WithField("path", path).Info("🔍 Testing directory writability")

	// Attempt to create directory structure with sudo if needed
	if err := privilegedMkdirAll(path, 0755); err != nil {
		log.WithError(err).Debugf("Failed to create directory %s", path)
		return false
	}

	// Test file creation and writing
	testFile := filepath.Join(path, ".test_write")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		log.WithError(err).Debugf("Failed to write test file in %s", path)
		_ = os.RemoveAll(path)
		return false
	}
	_ = os.Remove(testFile)
	return true
}

// privilegedMkdirAll creates directories with sudo if not root
func privilegedMkdirAll(path string, perm os.FileMode) error {
	log.WithFields(log.Fields{
		"path": path,
		"perm": perm,
	}).Info("📂 Creating directory (with sudo if needed)")

	if os.Getuid() != 0 {
		// Use sudo for mkdir -p
		cmd := exec.Command("sudo", "mkdir", "-p", path)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("sudo mkdir failed: %v, output: %s", err, string(output))
		}
		// Use sudo for chmod
		cmd = exec.Command("sudo", "chmod", fmt.Sprintf("%o", perm), path)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("sudo chmod failed: %v, output: %s", err, string(output))
		}
	} else {
		// Directly create directory as root
		if err := os.MkdirAll(path, perm); err != nil {
			return fmt.Errorf("mkdir failed: %w", err)
		}
	}
	return nil
}

// processDeviceConfig processes device-related environment variables
func processDeviceConfig() *DeviceConfig {
	cfg := &DeviceConfig{
		EncryptedDevice: os.Getenv("BLOCK_DEVICE"),
		BootDevice:      os.Getenv("BOOT_DEVICE"),
		RootFsType:      os.Getenv("ROOT_FS_TYPE"),
		BootFsType:      os.Getenv("BOOT_FS_TYPE"),
	}

	// Set default values if environment variables are not provided
	if cfg.EncryptedDevice == "" {
		cfg.EncryptedDevice = "/dev/sda3" // Default encrypted root partition
		log.Warn("Using default encrypted device: /dev/sda3 (ext4 with LUKS)")
	}
	if cfg.BootDevice == "" {
		cfg.BootDevice = "/dev/sda2" // Default boot partition
		log.Warn("Using default boot device: /dev/sda2 (ext4)")
	}

	// Set filesystem type defaults
	if cfg.RootFsType == "" {
		cfg.RootFsType = "ext4" // Default root filesystem
		log.Warn("Using default root filesystem: ext4")
	}
	if cfg.BootFsType == "" {
		cfg.BootFsType = "ext4" // Default boot filesystem
		log.Warn("Using default boot filesystem: ext4")
	}

	// Validate required configuration
	if cfg.EncryptedDevice == "" {
		logDeviceInfo()
		log.Fatal("❌ BLOCK_DEVICE must be specified")
	}

	log.WithFields(log.Fields{
		"encrypted_device": cfg.EncryptedDevice,
		"boot_device":      cfg.BootDevice,
		"root_fs_type":     cfg.RootFsType,
		"boot_fs_type":     cfg.BootFsType,
	}).Info("📌 Using device configuration")

	return cfg
}

// processExecConfig processes execution-related environment variables
func processExecConfig() *ExecConfig {
	return &ExecConfig{
		Command:         os.Getenv("CMD_LINE"),
		Interpreter:     os.Getenv("DEFAULT_INTERPRETER"),
		ChrootPath:      os.Getenv("CHROOT"),
		UpdateResolv:    os.Getenv("UPDATE_RESOLV_CONF") == "true",
		DefaultRootPath: "/mnt/root",
	}
}

// executeWorkflow orchestrates the entire execution process
func executeWorkflow(ctx context.Context, mountCfg *MountConfig, devCfg *DeviceConfig, execCfg *ExecConfig) error {
	// Create mount directories with appropriate permissions
	log.Info("🛠️ Creating mount directories")
	if err := createMountDirs(mountCfg.RootPath, mountCfg.BootPath); err != nil {
		return fmt.Errorf("failed to create mount directories: %w", err)
	}

	// Handle LUKS if needed
	var mappedDevice string

	if devCfg.BootDevice == "" {
		return fmt.Errorf("boot device required for LUKS operations")
	}

	device, err := handleLUKS(ctx, devCfg, mountCfg)
	if err != nil {
		return fmt.Errorf("LUKS handling failed: %w", err)
	}
	mappedDevice = device
	defer cleanupLUKS(mountCfg.LuksName)

	// Mount the appropriate device
	targetDevice := devCfg.EncryptedDevice
	if mappedDevice != "" {
		targetDevice = mappedDevice
	}

	// Mount the device with retry logic
	log.Info("⏳ Attempting to mount device (with retries)")
	if err := mountWithRetry(targetDevice, mountCfg.RootPath, devCfg.RootFsType, 3); err != nil {
		return fmt.Errorf("mount failed: %w", err)
	}
	defer unmountDevice(mountCfg.RootPath)

	// Handle chroot if requested
	if execCfg.ChrootPath != "" {
		log.Info("🏠 Setting up chroot environment")
		if err := setupChrootEnvironment(mountCfg.RootPath, execCfg); err != nil {
			return fmt.Errorf("chroot setup failed: %w", err)
		}
		defer cleanupChrootEnvironment(mountCfg.RootPath)
	}

	// Execute the command
	log.Info("🚀 Executing configured command")
	return executeCommand(execCfg)
}

// handleLUKS manages LUKS encrypted device operations
func handleLUKS(ctx context.Context, devCfg *DeviceConfig, mountCfg *MountConfig) (string, error) {
	log.Info("🔐 Handling LUKS encrypted device")

	// Mount boot partition with retry logic
	log.Info("⏳ Mounting boot partition (with retries)")
	if err := mountWithRetry(devCfg.BootDevice, mountCfg.BootPath, devCfg.BootFsType, 3); err != nil {
		return "", fmt.Errorf("failed to mount boot device: %w", err)
	}
	defer unmountDevice(mountCfg.BootPath)

	// Verify LUKS keyfile exists and has proper permissions
	fullKeyPath := filepath.Join(mountCfg.BootPath, mountCfg.KeyFile)
	log.WithField("key_path", fullKeyPath).Info("🔑 Verifying LUKS keyfile")
	if err := verifyKeyfile(fullKeyPath); err != nil {
		return "", fmt.Errorf("LUKS keyfile verification failed: %w", err)
	}

	// Open LUKS device
	log.Info("🔓 Opening LUKS encrypted device")
	if err := runPrivileged("cryptsetup", "luksOpen", devCfg.EncryptedDevice, mountCfg.LuksName, "--key-file", fullKeyPath); err != nil {
		return "", fmt.Errorf("failed to open LUKS device: %w", err)
	}

	log.WithFields(log.Fields{
		"source_device": devCfg.EncryptedDevice,
		"mapped_device": mountCfg.MappedDevice,
	}).Info("✅ LUKS device unlocked")

	return mountCfg.MappedDevice, nil
}

// cleanupLUKS closes a mapped LUKS device
func cleanupLUKS(name string) {
	log.WithField("luks_name", name).Info("🔒 Closing LUKS device")
	if err := runPrivileged("cryptsetup", "luksClose", name); err != nil {
		log.WithError(err).Warn("⚠️ Failed to close LUKS device")
	}
}

// mountWithRetry attempts to mount a device with multiple retries
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

// verifyDevice checks if a path is a valid block device
func verifyDevice(device string) error {
	log.WithField("device", device).Info("🔍 Verifying device")
	info, err := os.Stat(device)
	if err != nil {
		return fmt.Errorf("device %s stat failed: %w", device, err)
	}

	if (info.Mode() & os.ModeDevice) == 0 {
		return fmt.Errorf("%s is not a device file", device)
	}

	return nil
}

// verifyKeyfile checks LUKS keyfile properties
func verifyKeyfile(keyFile string) error {
	log.WithField("key_file", keyFile).Info("🔐 Verifying keyfile")
	info, err := os.Stat(keyFile)
	if err != nil {
		return fmt.Errorf("keyfile stat failed: %w", err)
	}

	// Check keyfile is not empty
	if info.Size() == 0 {
		return fmt.Errorf("keyfile is empty")
	}

	// Check keyfile permissions (should be 0400)
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
func setupChrootEnvironment(rootPath string, execCfg *ExecConfig) error {
	log.WithField("root_path", rootPath).Info("Setting up chroot environment")

	// 1. First ensure all mount points are unmounted and LUKS device is closed
	cleanup := func() {
		unmountOrder := []string{
			filepath.Join(rootPath, "sys"),
			filepath.Join(rootPath, "proc"),
			filepath.Join(rootPath, "dev"),
		}

		for _, mountPoint := range unmountOrder {
			if err := unmountWithRetry(mountPoint, 3); err != nil {
				log.WithError(err).Warnf("Failed to unmount %s", mountPoint)
			}
		}

		// Ensure LUKS device is closed with retries
		for i := 0; i < 3; i++ {
			if err := runPrivileged("cryptsetup", "luksClose", "cryptroot"); err == nil {
				break
			}
			time.Sleep(time.Second * time.Duration(i+1))
		}
	}
	defer cleanup()

	// 2. Create required directories with proper permissions
	requiredDirs := []string{
		filepath.Join(rootPath, "dev"),
		filepath.Join(rootPath, "proc"),
		filepath.Join(rootPath, "sys"),
		filepath.Join(rootPath, "etc"),
	}

	for _, dir := range requiredDirs {
		if err := privilegedMkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// 3. Mount special filesystems with retries and fallback
	if err := mountSpecialFilesystems(rootPath); err != nil {
		return err
	}

	// 4. Handle resolv.conf if requested
	if execCfg.UpdateResolv {
		if err := handleResolvConf(rootPath); err != nil {
			return err
		}
	}

	// 5. Attempt chroot with multiple strategies
	if err := attemptChroot(rootPath); err != nil {
		return err
	}

	return nil
}

func mountSpecialFilesystems(rootPath string) error {
	mountOperations := []struct {
		name    string
		source  string
		target  string
		fsType  string
		options string
	}{
		{
			name:    "devtmpfs",
			source:  "none",
			target:  filepath.Join(rootPath, "dev"),
			fsType:  "devtmpfs",
			options: "mode=0755,nosuid,noexec",
		},
		{
			name:    "proc",
			source:  "none",
			target:  filepath.Join(rootPath, "proc"),
			fsType:  "proc",
			options: "nosuid,noexec,nodev",
		},
		{
			name:    "sysfs",
			source:  "none",
			target:  filepath.Join(rootPath, "sys"),
			fsType:  "sysfs",
			options: "nosuid,noexec,nodev,ro",
		},
	}

	for _, op := range mountOperations {
		var lastErr error
		for attempt := 1; attempt <= 3; attempt++ {
			log.WithFields(log.Fields{
				"attempt": attempt,
				"target":  op.target,
				"type":    op.fsType,
			}).Info("Mounting special filesystem")

			args := []string{"-t", op.fsType}
			if op.options != "" {
				args = append(args, "-o", op.options)
			}
			args = append(args, op.source, op.target)

			if err := runPrivileged("mount", args...); err == nil {
				break
			}

			time.Sleep(time.Second * time.Duration(attempt))
		}

		if lastErr != nil {
			return fmt.Errorf("failed to mount %s at %s: %w", op.fsType, op.target, lastErr)
		}
	}
	return nil
}

func handleResolvConf(rootPath string) error {
	resolvPath := filepath.Join(rootPath, "etc/resolv.conf")
	if err := os.WriteFile(resolvPath, nil, 0644); err != nil {
		return fmt.Errorf("failed to create empty resolv.conf: %w", err)
	}

	if err := runPrivileged("mount", "--bind", "/etc/resolv.conf", resolvPath); err != nil {
		return fmt.Errorf("failed to bind mount resolv.conf: %w", err)
	}
	return nil
}

func attemptChroot(rootPath string) error {
	// First verify basic chroot structure exists
	requiredPaths := []string{
		filepath.Join(rootPath, "bin/sh"),
		filepath.Join(rootPath, "bin/ls"),
	}

	for _, path := range requiredPaths {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("missing required path %s: %w", path, err)
		}
	}

	// Try privileged chroot with a test command
	testCmd := "/bin/sh -c 'echo \"Chroot successful\" && exit 0'"
	if err := runPrivileged("chroot", rootPath, "/bin/sh", "-c", testCmd); err == nil {
		return nil
	} else {
		log.WithError(err).Warn("Direct chroot attempt failed")
	}

	// Enhanced nsenter fallback
	if nsenterPath, err := exec.LookPath("nsenter"); err == nil {
		cmd := exec.Command(nsenterPath, "-t", "1", "-m", "-u", "-n", "-i", "chroot", rootPath, "/bin/sh", "-c", testCmd)
		if output, err := cmd.CombinedOutput(); err == nil {
			return nil
		} else {
			log.WithFields(log.Fields{
				"error":  err,
				"output": string(output),
			}).Warn("nsenter chroot attempt failed")
		}
	}

	// Additional debug: list chroot contents
	if contents, err := runPrivilegedGetOutput("ls", "-la", rootPath); err == nil {
		log.WithField("contents", contents).Debug("Chroot directory contents")
	}

	return fmt.Errorf("all chroot attempts failed - verify /bin/sh exists in %s", rootPath)
}

func runPrivilegedGetOutput(command string, args ...string) (string, error) {
	var stdout, stderr bytes.Buffer

	fullArgs := append([]string{"--"}, args...)
	cmd := exec.Command("sudo", append([]string{command}, fullArgs...)...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := strings.TrimSpace(stdout.String())
	if err != nil {
		return "", fmt.Errorf("%s: %w (stderr: %s)", cmd.String(), err, stderr.String())
	}
	return output, nil
}

func unmountWithRetry(mountPoint string, maxAttempts int) error {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Try normal unmount first
		if err := runPrivileged("umount", mountPoint); err == nil {
			return nil
		}

		// Then try lazy unmount
		if err := runPrivileged("umount", "-l", mountPoint); err == nil {
			return nil
		}

		time.Sleep(time.Second * time.Duration(attempt))
	}
	return fmt.Errorf("failed to unmount %s after %d attempts: %w", mountPoint, maxAttempts, lastErr)
}

// mountDevice performs the actual mount operation with validation
func mountDevice(device, mountPoint, fsType string) error {
	// Verify device exists and is a block device
	if err := verifyDevice(device); err != nil {
		return err
	}

	// Prepare mount arguments
	args := []string{"-v"} // Verbose output
	if fsType != "" {
		args = append(args, "-t", fsType)
	}

	args = append(args, device, mountPoint)

	// Execute mount command with appropriate privileges
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

func unmountDevice(mountPoint string) error {
	// First try normal unmount
	if err := runPrivileged("umount", mountPoint); err == nil {
		return nil
	}

	// Fall back to forced unmount
	if err := runPrivileged("umount", "-f", mountPoint); err == nil {
		return nil
	}

	// Finally try lazy unmount
	return runPrivileged("umount", "-l", mountPoint)
}

// cleanupChrootEnvironment cleans up the chroot environment
func cleanupChrootEnvironment(rootPath string) {
	log.WithField("root_path", rootPath).Info("🧹 Cleaning up chroot environment")

	// Unmount special filesystems in reverse order
	specialDirs := []string{
		filepath.Join(rootPath, "sys"),
		filepath.Join(rootPath, "proc"),
		filepath.Join(rootPath, "dev"),
	}

	for _, dir := range specialDirs {
		log.WithField("path", dir).Info("Unmounting special directory")
		if err := unmountDevice(dir); err != nil {
			log.WithError(err).Error("Failed to unmount directory")
		}
	}
}

// executeCommand runs the configured command
func executeCommand(execCfg *ExecConfig) error {
	var cmd *exec.Cmd

	log.WithFields(log.Fields{
		"command":     execCfg.Command,
		"interpreter": execCfg.Interpreter,
		"chroot":      execCfg.ChrootPath,
	}).Info("⚡ Executing command")

	if execCfg.Interpreter != "" {
		log.WithField("interpreter", execCfg.Interpreter).Info("Using interpreter")
		parts := strings.Fields(execCfg.Interpreter)
		parts = append(parts, execCfg.Command)
		cmd = exec.Command(parts[0], parts[1:]...)
	} else {
		// Handle multiple commands separated by semicolons
		commands := strings.Split(execCfg.Command, ";")
		for _, command := range commands {
			command = strings.TrimSpace(command)
			if command == "" {
				continue
			}

			parts := strings.Fields(command)
			if len(parts) == 0 {
				continue
			}

			cmd = exec.Command(parts[0], parts[1:]...)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			log.WithField("command", cmd.String()).Info("Executing command")
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("command failed: %w", err)
			}
		}
		return nil
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	log.WithField("command", cmd.String()).Info("Executing command")
	return cmd.Run()
}

// createMountDirs creates mount point directories with standard permissions
func createMountDirs(paths ...string) error {
	log.WithField("paths", paths).Info("📂 Creating mount directories")
	for _, path := range paths {
		log.WithField("directory", path).Debug("Creating directory")
		if err := privilegedMkdirAll(path, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", path, err)
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

	// Execute command and capture output
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

// logDeviceInfo gathers and logs detailed device information
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
