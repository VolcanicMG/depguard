package tty

import "syscall"

// macOS reads terminal attributes with TIOCGETA.
const ioctlReadTermios = syscall.TIOCGETA
