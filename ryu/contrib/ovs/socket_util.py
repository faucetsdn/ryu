# Copyright (c) 2010, 2012 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import errno
import os
import select
import socket
import sys

import ovs.fatal_signal
import ovs.poller
import ovs.vlog

vlog = ovs.vlog.Vlog("socket_util")


def make_unix_socket(style, nonblock, bind_path, connect_path):
    """Creates a Unix domain socket in the given 'style' (either
    socket.SOCK_DGRAM or socket.SOCK_STREAM) that is bound to 'bind_path' (if
    'bind_path' is not None) and connected to 'connect_path' (if 'connect_path'
    is not None).  If 'nonblock' is true, the socket is made non-blocking.

    Returns (error, socket): on success 'error' is 0 and 'socket' is a new
    socket object, on failure 'error' is a positive errno value and 'socket' is
    None."""

    try:
        sock = socket.socket(socket.AF_UNIX, style)
    except socket.error, e:
        return get_exception_errno(e), None

    try:
        if nonblock:
            set_nonblocking(sock)
        if bind_path is not None:
            # Delete bind_path but ignore ENOENT.
            try:
                os.unlink(bind_path)
            except OSError, e:
                if e.errno != errno.ENOENT:
                    return e.errno, None

            ovs.fatal_signal.add_file_to_unlink(bind_path)
            sock.bind(bind_path)

            try:
                if sys.hexversion >= 0x02060000:
                    os.fchmod(sock.fileno(), 0700)
                else:
                    os.chmod("/dev/fd/%d" % sock.fileno(), 0700)
            except OSError, e:
                pass
        if connect_path is not None:
            try:
                sock.connect(connect_path)
            except socket.error, e:
                if get_exception_errno(e) != errno.EINPROGRESS:
                    raise
        return 0, sock
    except socket.error, e:
        sock.close()
        if bind_path is not None:
            ovs.fatal_signal.unlink_file_now(bind_path)
        return get_exception_errno(e), None


def check_connection_completion(sock):
    p = ovs.poller.SelectPoll()
    p.register(sock, ovs.poller.POLLOUT)
    if len(p.poll(0)) == 1:
        return get_socket_error(sock)
    else:
        return errno.EAGAIN

def inet_parse_active(target, default_port):
    """Splits the given target ip-address at the last occuring ':' to
    separate address from port. Ipv6 addresses may be given with square
    brackets at the beginning and the end.

    example:
    ipv4 target: "tcp:127.0.0.1:6632"
    ipv6 target: "tcp:[2001:DB8:0:0::1]:6632"
    """
    address = target.rsplit(":",1)
    host_name = address[0]
    host_name = host_name.rstrip("]")
    host_name = host_name.lstrip("[")

    if not host_name:
        raise ValueError("%s: bad peer name format" % target)
    if len(address) >= 2:
        port = int(address[1])
    elif default_port:
        port = default_port
    else:
        raise ValueError("%s: port number must be specified" % target)
    return (host_name, port)

def inet_open_active(style, target, default_port, dscp):
    address = inet_parse_active(target, default_port)
    try:
        sock = socket.socket(socket.AF_INET, style, 0)
    except socket.error, e:
        return get_exception_errno(e), None

    try:
        set_nonblocking(sock)
        set_dscp(sock, dscp)
        try:
            sock.connect(address)
        except socket.error, e:
            if get_exception_errno(e) != errno.EINPROGRESS:
                raise
        return 0, sock
    except socket.error, e:
        sock.close()
        return get_exception_errno(e), None

def inet_open_active_stream(target, default_port, dscp):
    address = inet_parse_active(target, default_port)
    try:
        sock = socket.create_connection(address)
    except socket.error, e:
        return get_exception_errno(e), None

    try:
        set_nonblocking(sock)
        set_dscp(sock, dscp)
        return 0, sock
    except socket.error, e:
        sock.close()
        return get_exception_errno(e), None

def get_socket_error(sock):
    """Returns the errno value associated with 'socket' (0 if no error) and
    resets the socket's error status."""
    return sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)


def get_exception_errno(e):
    """A lot of methods on Python socket objects raise socket.error, but that
    exception is documented as having two completely different forms of
    arguments: either a string or a (errno, string) tuple.  We only want the
    errno."""
    if type(e.args) == tuple:
        return e.args[0]
    else:
        return errno.EPROTO


null_fd = -1


def get_null_fd():
    """Returns a readable and writable fd for /dev/null, if successful,
    otherwise a negative errno value.  The caller must not close the returned
    fd (because the same fd will be handed out to subsequent callers)."""
    global null_fd
    if null_fd < 0:
        try:
            null_fd = os.open("/dev/null", os.O_RDWR)
        except OSError, e:
            vlog.err("could not open /dev/null: %s" % os.strerror(e.errno))
            return -e.errno
    return null_fd


def write_fully(fd, buf):
    """Returns an (error, bytes_written) tuple where 'error' is 0 on success,
    otherwise a positive errno value, and 'bytes_written' is the number of
    bytes that were written before the error occurred.  'error' is 0 if and
    only if 'bytes_written' is len(buf)."""
    bytes_written = 0
    if len(buf) == 0:
        return 0, 0
    while True:
        try:
            retval = os.write(fd, buf)
            assert retval >= 0
            if retval == len(buf):
                return 0, bytes_written + len(buf)
            elif retval == 0:
                vlog.warn("write returned 0")
                return errno.EPROTO, bytes_written
            else:
                bytes_written += retval
                buf = buf[:retval]
        except OSError, e:
            return e.errno, bytes_written


def set_nonblocking(sock):
    try:
        sock.setblocking(0)
    except socket.error, e:
        vlog.err("could not set nonblocking mode on socket: %s"
                 % os.strerror(get_socket_error(e)))


def set_dscp(sock, dscp):
    if dscp > 63:
        raise ValueError("Invalid dscp %d" % dscp)
    val = dscp << 2
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, val)
