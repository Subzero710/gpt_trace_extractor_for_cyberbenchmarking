"""Exec-only child launcher for a controlling Unix PTY."""
import fcntl
import os
import termios


def main():
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    os.execv("/bin/bash", ["/bin/bash", "-i"])


if __name__ == "__main__":
    main()
