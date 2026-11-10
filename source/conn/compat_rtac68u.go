//go:build rtac68u

package conn

// RTAC68UCompat disables batch UDP and TUN offloads for ASUS Linux 2.6.36.
// sendmmsg was introduced in Linux 3.0; use recvmsg/sendmsg instead.
const RTAC68UCompat = true
