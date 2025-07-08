package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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

// FileConfig holds configuration for file operations
type FileConfig struct {
	Path    string      // Destination path for file operations
	Content string      // Content to write to file
	Mode    os.FileMode // File permissions mode
	DirMode os.FileMode // Directory permissions mode
	UID     int         // User ID for ownership
	GID     int         // Group ID for ownership
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

	// Record startup time and log initialization info
	startTime := time.Now()
	logStartupInfo()

	// Ensure completion logs are always recorded
	defer func() {
		logCompletionInfo(startTime)
	}()

	log.Info("✅ Running writefile with LUKS Support")

	// Check and log user privileges
	checkPrivileges()

	// Initialize mount configuration with defaults
	mountCfg := &MountConfig{
		LuksName: "cryptroot", // Default LUKS device name
		RootPath: determineMountPath("root"),
		BootPath: determineMountPath("boot"),
	}
	mountCfg.MappedDevice = "/dev/mapper/" + mountCfg.LuksName
	mountCfg.KeyFile = filepath.Join(mountCfg.BootPath, "root_crypt.key")

	// Process device configuration from environment variables
	devCfg := processDeviceConfig()
	// Process file configuration from environment variables
	fileCfg := processFileConfig()

	// Execute main workflow with the configured parameters
	if err := executeWorkflow(mountCfg, devCfg, fileCfg); err != nil {
		log.WithError(err).Fatal("❌ Workflow execution failed")
	}
}

// configureLogging sets up the logging system with custom formatting and multi-output
func configureLogging() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339Nano,
		PadLevelText:    true,
	})
	log.SetLevel(log.DebugLevel) // Enable maximum logging level

	// Set up multi-writer to output to both stdout and a buffer
	var logBuffer bytes.Buffer
	mw := io.MultiWriter(os.Stdout, &logBuffer)
	log.SetOutput(mw)
}

// logStartupInfo records initial system and process information
func logStartupInfo() {
	// Get all environment variables
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
		"start_time":  time.Now().Format(time.RFC3339Nano),
		"pid":         os.Getpid(),
		"ppid":        os.Getppid(),
		"uid":         os.Getuid(),
		"gid":         os.Getgid(),
		"go_version":  runtime.Version(),
		"environment": envVars,
	}).Info("🚀 Starting secure disk configuration")
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
	// Attempt to create directory structure
	if err := os.MkdirAll(path, 0755); err != nil {
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

// processDeviceConfig processes device-related environment variables
func processDeviceConfig() *DeviceConfig {
	cfg := &DeviceConfig{
		EncryptedDevice: os.Getenv("ENCRYPTED_DISK"),
		BootDevice:      os.Getenv("BOOT_DISK"),
		RootFsType:      os.Getenv("ROOT_FS_TYPE"),
		BootFsType:      os.Getenv("BOOT_FS_TYPE"),
	}

	// Set default values if environment variables are not provided
	if cfg.EncryptedDevice == "" {
		cfg.EncryptedDevice = "/dev/sda3" // Default encrypted root partition
		log.Warn("Using default encrypted device: /dev/sda3")
	}
	if cfg.BootDevice == "" {
		cfg.BootDevice = "/dev/sda2" // Default boot partition
		log.Warn("Using default boot device: /dev/sda2")
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
	if cfg.EncryptedDevice == "" || cfg.BootDevice == "" {
		logDeviceInfo()
		log.Fatal("❌ ENCRYPTED_DISK and BOOT_DISK must be specified or defaults will be used")
	}

	log.WithFields(log.Fields{
		"encrypted_device": cfg.EncryptedDevice,
		"boot_device":      cfg.BootDevice,
		"root_fs_type":     cfg.RootFsType,
		"boot_fs_type":     cfg.BootFsType,
	}).Info("📌 Using device configuration")

	return cfg
}

// processFileConfig processes file-related environment variables
func processFileConfig() *FileConfig {
	fileMode, dirMode := parseFileModes(
		os.Getenv("FILE_MODE"),
		os.Getenv("DIR_MODE"),
	)

	uid, gid := parseOwnership(
		os.Getenv("FILE_UID"),
		os.Getenv("FILE_GID"),
	)

	return &FileConfig{
		Path:    os.Getenv("DEST_PATH"),
		Content: os.Getenv("CONTENTS"),
		Mode:    fileMode,
		DirMode: dirMode,
		UID:     uid,
		GID:     gid,
	}
}

// parseFileModes converts string representations to FileMode values
func parseFileModes(modeStr, dirModeStr string) (os.FileMode, os.FileMode) {
	fileMode := os.FileMode(0644) // Default file permissions
	if modeStr != "" {
		modeVal, err := strconv.ParseUint(modeStr, 8, 32)
		if err != nil {
			log.WithError(err).Fatalf("Invalid FILE_MODE: %s", modeStr)
		}
		fileMode = os.FileMode(modeVal)
	}

	dirMode := os.FileMode(0755) // Default directory permissions
	if dirModeStr != "" {
		dirModeVal, err := strconv.ParseUint(dirModeStr, 8, 32)
		if err != nil {
			log.WithError(err).Fatalf("Invalid DIR_MODE: %s", dirModeStr)
		}
		dirMode = os.FileMode(dirModeVal)
	}

	log.WithFields(log.Fields{
		"file_mode": fmt.Sprintf("%#o", fileMode),
		"dir_mode":  fmt.Sprintf("%#o", dirMode),
	}).Debug("Processed file modes")
	return fileMode, dirMode
}

// parseOwnership converts string UID/GID to integers
func parseOwnership(uidStr, gidStr string) (int, int) {
	uid := 0 // Default root UID
	if uidStr != "" {
		var err error
		uid, err = strconv.Atoi(uidStr)
		if err != nil {
			log.WithError(err).Fatalf("Invalid FILE_UID: %s", uidStr)
		}
	}

	gid := 0 // Default root GID
	if gidStr != "" {
		var err error
		gid, err = strconv.Atoi(gidStr)
		if err != nil {
			log.WithError(err).Fatalf("Invalid FILE_GID: %s", gidStr)
		}
	}

	log.WithFields(log.Fields{
		"uid": uid,
		"gid": gid,
	}).Debug("Processed ownership settings")
	return uid, gid
}

// executeWorkflow orchestrates the entire disk setup process
func executeWorkflow(mountCfg *MountConfig, devCfg *DeviceConfig, fileCfg *FileConfig) error {
	// Create mount directories with appropriate permissions
	if err := createMountDirs(mountCfg.RootPath, mountCfg.BootPath); err != nil {
		return fmt.Errorf("failed to create mount directories: %w", err)
	}

	// Mount boot partition with retry logic
	if err := mountWithRetry(devCfg.BootDevice, mountCfg.BootPath, devCfg.BootFsType, 3); err != nil {
		return fmt.Errorf("failed to mount boot device: %w", err)
	}
	defer unmountDevice(mountCfg.BootPath)

	// Verify LUKS keyfile exists and has proper permissions
	if err := verifyKeyfile(mountCfg.KeyFile); err != nil {
		return fmt.Errorf("LUKS keyfile verification failed: %w", err)
	}

	// Handle LUKS device operations (open, map, etc.)
	if err := handleLUKSOperations(devCfg.EncryptedDevice, mountCfg.LuksName, mountCfg.KeyFile, mountCfg.MappedDevice); err != nil {
		return err
	}
	defer closeLUKSDevice(mountCfg.LuksName)

	// Mount root partition with retry logic
	if err := mountWithRetry(mountCfg.MappedDevice, mountCfg.RootPath, devCfg.RootFsType, 3); err != nil {
		return fmt.Errorf("failed to mount root partition: %w", err)
	}
	defer unmountDevice(mountCfg.RootPath)

	// Perform requested file operations in the mounted root
	return handleFileOperations(mountCfg.RootPath, fileCfg)
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

// unmountDevice unmounts a filesystem from the specified mount point
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

// handleLUKSOperations manages LUKS device mapping operations
func handleLUKSOperations(blockDevice, luksName, keyFile, mappedDevice string) error {
	log.WithFields(log.Fields{
		"block_device": blockDevice,
		"luks_name":    luksName,
		"key_file":     keyFile,
	}).Info("🔓 Attempting to unlock LUKS device")

	// Prepare cryptsetup command arguments
	cmdArgs := []string{
		"luksOpen",
		blockDevice,
		luksName,
		"--key-file", keyFile,
		"--verbose",
	}

	// Execute cryptsetup command
	if err := runPrivileged("cryptsetup", cmdArgs...); err != nil {
		// Log detailed failure information
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

// handleFileOperations manages file creation and directory structure
func handleFileOperations(basePath string, cfg *FileConfig) error {
	// Split path into directory and filename components
	dirPath, fileName := filepath.Split(cfg.Path)
	if fileName == "" {
		return fmt.Errorf("DEST_PATH must include a file name")
	}

	// Create directory structure with proper permissions
	if err := createDirectoryStructure(basePath, dirPath, cfg.DirMode, cfg.UID, cfg.GID); err != nil {
		return fmt.Errorf("failed to create directory structure: %w", err)
	}

	// Write file with specified content and permissions
	fullPath := filepath.Join(basePath, cfg.Path)
	if err := writeFileWithPermissions(fullPath, cfg.Content, cfg.Mode, cfg.UID, cfg.GID); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// createDirectoryStructure builds directory hierarchy with proper permissions
func createDirectoryStructure(basePath, relPath string, mode os.FileMode, uid, gid int) error {
	currentPath := basePath
	parts := strings.Split(relPath, string(filepath.Separator))

	for _, part := range parts {
		if part == "" {
			continue
		}

		currentPath = filepath.Join(currentPath, part)
		if err := createAndChownDir(currentPath, mode, uid, gid); err != nil {
			return err
		}
	}

	return nil
}

// createAndChownDir creates a directory and sets its permissions/ownership
func createAndChownDir(path string, mode os.FileMode, uid, gid int) error {
	// Check if directory already exists
	if info, err := os.Stat(path); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s exists but is not a directory", path)
		}
		return nil
	}

	// Create directory with sudo
	if err := runPrivileged("mkdir", "-p", path); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}

	// Set directory permissions with sudo
	if err := runPrivileged("chmod", fmt.Sprintf("%o", mode), path); err != nil {
		return fmt.Errorf("failed to set permissions for %s: %w", path, err)
	}

	// Set directory ownership with sudo
	if err := runPrivileged("chown", fmt.Sprintf("%d:%d", uid, gid), path); err != nil {
		return fmt.Errorf("failed to set ownership for %s: %w", path, err)
	}

	log.WithFields(log.Fields{
		"path":        path,
		"permissions": fmt.Sprintf("%#o", mode),
		"uid":         uid,
		"gid":         gid,
	}).Debug("Created directory with permissions")
	return nil
}

// createMountDirs creates mount point directories with standard permissions
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

// writeFileWithPermissions writes content to a file with specified permissions and ownership
func writeFileWithPermissions(path, content string, mode os.FileMode, uid, gid int) error {
	// Create temp file in secure location
	tempFile, err := os.CreateTemp("", "tmpfile-")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tempFile.Name())

	// Write content to temp file
	if _, err := tempFile.WriteString(content); err != nil {
		return fmt.Errorf("failed to write to temp file: %w", err)
	}
	tempFile.Close()

	// Move file to destination with sudo
	if err := runPrivileged("mv", tempFile.Name(), path); err != nil {
		return fmt.Errorf("failed to move file to destination: %w", err)
	}

	// Set file permissions with sudo
	if err := runPrivileged("chmod", fmt.Sprintf("%o", mode), path); err != nil {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	// Set file ownership with sudo
	if err := runPrivileged("chown", fmt.Sprintf("%d:%d", uid, gid), path); err != nil {
		return fmt.Errorf("failed to set file ownership: %w", err)
	}

	// Verify file was written correctly
	verifyFile(path, content, mode, uid, gid)
	return nil
}

// verifyFile checks that a file was written with expected properties
func verifyFile(path, expectedContent string, expectedMode os.FileMode, expectedUID, expectedGID int) {
	info, err := os.Stat(path)
	if err != nil {
		log.WithError(err).Warn("⚠️ Failed to verify written file")
		return
	}

	content, err := os.ReadFile(path)
	if err != nil {
		log.WithError(err).Warn("⚠️ Failed to read file for verification")
		return
	}

	if string(content) != expectedContent {
		log.Warn("⚠️ File content verification failed")
	}

	log.WithFields(log.Fields{
		"file_path":   path,
		"size_bytes":  info.Size(),
		"permissions": fmt.Sprintf("%#o", info.Mode().Perm()),
		"uid":         expectedUID,
		"gid":         expectedGID,
	}).Info("✅ File written and verified")
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
