package tty

import "syscall"

// Linux reads terminal attributes with TCGETS.
const ioctlReadTermios = syscall.TCGETS
