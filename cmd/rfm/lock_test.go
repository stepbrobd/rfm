package main

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLockPinRefusesASecondHolder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pin")

	release, err := lockPin(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("pin directory not created: %v", err)
	}

	// the lock is on the directory, so another name for it is refused too
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, dir + "/", link} {
		if _, err := lockPin(path); err == nil || !strings.Contains(err.Error(), "in use by another agent") {
			t.Fatalf("second lock on %s = %v, want it refused", path, err)
		}
	}

	release()
	release, err = lockPin(link)
	if err != nil {
		t.Fatalf("lock after release = %v", err)
	}
	release()
}

// TestLockPinHelper holds the pin lock named by RFM_TEST_PIN_LOCK for
// TestLockPinIsReleasedWhenTheHolderDies until it is killed
func TestLockPinHelper(t *testing.T) {
	dir := os.Getenv("RFM_TEST_PIN_LOCK")
	if dir == "" {
		t.Skip("helper process only")
	}
	if _, err := lockPin(dir); err != nil {
		t.Fatal(err)
	}
	os.Stdout.WriteString("locked\n")
	time.Sleep(time.Hour)
}

func TestLockPinIsReleasedWhenTheHolderDies(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pin")

	cmd := exec.Command(os.Args[0], "-test.run=^TestLockPinHelper$")
	cmd.Env = append(os.Environ(), "RFM_TEST_PIN_LOCK="+dir)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatalf("helper said %q, %v", line, err)
	}

	if _, err := lockPin(dir); err == nil {
		t.Fatal("lock taken while another process holds it")
	}
	// a killed agent runs no cleanup, the kernel drops its lock
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	release, err := lockPin(dir)
	if err != nil {
		t.Fatalf("lock after the holder died = %v", err)
	}
	release()
}
